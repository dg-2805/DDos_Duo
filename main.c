// Enable GNU extensions for recvmmsg/sendmmsg
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "dns_lb_common.h"
#include "dns_protocol.h"
#include "backend_manager.h"
#include "health_checker.h"
#include "dns_parser.h"

#define CONFIG_FILE "config.json"
#define BUFFER_SIZE 512
#define BATCH_SZ 128
#define MAX_BACKEND_BATCH 64

static volatile int running = 1;
static int dns_socket = -1;
static int g_verbose = 0; // Global verbosity
static uint16_t g_listen_port = 53; // Default DNS port

// Global backend manager instance
struct backend_manager *g_bm = NULL;

void signal_handler(int sig) {
    if (g_verbose) printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

// Create DNS socket
int create_dns_socket(uint16_t port, int reuse_port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    // Set SO_REUSEADDR
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }
    // Optionally set SO_REUSEPORT for multi-worker fanout
    if (reuse_port) {
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
            perror("setsockopt SO_REUSEPORT");
            // continue even if it fails
        }
    }

    // Enlarge socket buffers (best-effort; kernel may clamp)
    int buf = 4 * 1024 * 1024;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    
    // Bind to port 53
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    // Set listener socket non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    if (g_verbose) printf("DNS socket bound to port %u\n", (unsigned)port);
    return sock;
}

// --- Persistent backend socket and query map implementation ---
#include <sys/epoll.h>
#include <sys/uio.h>
#include <time.h>
#define MAX_BACKENDS 16
#define MAX_PENDING_QUERIES 65536

struct backend_sock {
    int fd;
    struct sockaddr_in addr;
    int connected; // 1 if connect() succeeded
};

struct query_map_entry {
    int in_use;
    uint16_t internal_id;
    uint16_t original_id;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int backend_index;
    uint64_t timestamp_ms;
};

struct worker_ctx {
    int sockfd;
    struct backend_sock backends[MAX_BACKENDS];
    int backend_count;
    struct query_map_entry qmap[MAX_PENDING_QUERIES];
    uint16_t next_internal_id;
    struct backend_manager *bm;
    // Small per-worker TTL cache
    
    // Cache constants
    #define CACHE_BUCKETS 2048
    #define CACHE_RESP_MAX 512
    struct cache_entry {
        int in_use;
        uint32_t hash;
        uint16_t qtype;
        char qname[256];
        uint64_t expires_ms;
        // Store response bytes with ID zeroed; we patch ID on send
        int resp_len;
        unsigned char resp[CACHE_RESP_MAX];
    } cache[CACHE_BUCKETS];
    uint32_t cache_ttl_ms; // default 5000ms or env override
};

// Utility: get current time in ms
static uint64_t now_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Optimized FNV-1a hash with fast path for common cases
static uint32_t fnv1a_hash(const char *s, uint16_t qtype) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        unsigned char c = *p;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        h ^= c;
        h *= 16777619u;
    }
    h ^= (uint32_t)qtype;
    h *= 16777619u;
    return h;
}

static inline uint32_t cache_index(uint32_t hash) {
    return hash & (CACHE_BUCKETS - 1);
}

static void cache_init(struct worker_ctx *ctx) {
    memset(ctx->cache, 0, sizeof(ctx->cache));
    // TTL from env or default 5000ms
    const char *e = getenv("LB_CACHE_TTL_MS");
    ctx->cache_ttl_ms = (e && *e) ? (uint32_t)atoi(e) : 5000u;
}

// Optimized cache lookup with fast path for common queries
static int cache_lookup_and_build(struct worker_ctx *ctx,
                                  const char *qname, uint16_t qtype,
                                  uint16_t id,
                                  unsigned char *out_buf, int out_cap) {
    uint32_t h = fnv1a_hash(qname, qtype);
    uint32_t idx = cache_index(h);
    struct cache_entry *ce = &ctx->cache[idx];
    uint64_t t = now_ms();
    if (ce->in_use && ce->hash == h && ce->qtype == qtype && ce->expires_ms > t) {
        if (strcasecmp(ce->qname, qname) == 0) {
            if (ce->resp_len <= out_cap) {
                memcpy(out_buf, ce->resp, (size_t)ce->resp_len);
                struct dns_header *hdr = (struct dns_header*)out_buf;
                hdr->id = htons(id);
                return ce->resp_len;
            }
        }
    }
    return -1;
}

// Store response into cache with ID zeroed
static void cache_store(struct worker_ctx *ctx, const char *qname, uint16_t qtype,
                        const unsigned char *resp, int resp_len) {
    if (!qname || !resp || resp_len <= 0 || resp_len > CACHE_RESP_MAX) return;
    uint32_t h = fnv1a_hash(qname, qtype);
    uint32_t idx = cache_index(h);
    struct cache_entry *ce = &ctx->cache[idx];
    // Copy
    ce->in_use = 1;
    ce->hash = h;
    ce->qtype = qtype;
    strncpy(ce->qname, qname, sizeof(ce->qname) - 1);
    ce->qname[sizeof(ce->qname) - 1] = '\0';
    ce->resp_len = resp_len;
    memcpy(ce->resp, resp, (size_t)resp_len);
    // Zero ID for patching on send
    if (resp_len >= (int)sizeof(struct dns_header)) {
        ((struct dns_header*)ce->resp)->id = 0;
    }
    ce->expires_ms = now_ms() + ctx->cache_ttl_ms;
}

// Setup persistent backend sockets for a worker
static void setup_backend_sockets_worker(struct worker_ctx *ctx) {
    struct lb_config config;
    backend_manager_get_stats(ctx->bm, &config, NULL, NULL);
    ctx->backend_count = config.backend_count;
    for (int i = 0; i < ctx->backend_count; ++i) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            perror("backend socket");
            exit(1);
        }
        // Enlarge socket buffers for backend sockets as well
        int buf = 4 * 1024 * 1024;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
        memset(&ctx->backends[i].addr, 0, sizeof(struct sockaddr_in));
        ctx->backends[i].addr.sin_family = AF_INET;
        ctx->backends[i].addr.sin_addr.s_addr = config.backends[i].ip_addr;
        ctx->backends[i].addr.sin_port = htons(config.backends[i].port);
        // Connect to backend to reduce per-send overhead and filter incoming packets
        if (connect(fd, (struct sockaddr*)&ctx->backends[i].addr, sizeof(ctx->backends[i].addr)) < 0) {
            perror("connect backend");
            ctx->backends[i].connected = 0; // continue without connect if it fails
        } else {
            ctx->backends[i].connected = 1;
        }
        ctx->backends[i].fd = fd;
    }
    ctx->next_internal_id = 1;
    cache_init(ctx);
}

// Allocate an internal_id mapped directly to qmap slot for O(1) lookups
static int alloc_internal_id(struct worker_ctx *ctx, uint16_t *out_id) {
    if (!out_id) return -1;
    // Try up to full space to find a free slot
    for (int tries = 0; tries < MAX_PENDING_QUERIES; ++tries) {
        uint16_t id = ctx->next_internal_id++;
        if (ctx->next_internal_id == 0) ctx->next_internal_id = 1; // skip 0
        if (!ctx->qmap[id].in_use) {
            *out_id = id;
            return 0;
        }
    }
    return -1;
}

// Forward DNS query to backend (non-blocking, persistent socket)
static int forward_to_backend_w(struct worker_ctx *ctx, unsigned char *query, int query_len, 
                      struct sockaddr_in *client_addr, socklen_t client_len) {
    if (!ctx || !query || query_len <= 0) return -1;
    int backend_index = backend_manager_select_backend(ctx->bm);
    if (backend_index < 0) return -1;
    if (backend_index >= ctx->backend_count) return -1;
    struct backend_sock *b = &ctx->backends[backend_index];

    // Rewrite DNS ID to internal
    struct dns_header *dns = (struct dns_header*)query;
    uint16_t original_id = ntohs(dns->id);
    uint16_t internal_id = 0;
    if (alloc_internal_id(ctx, &internal_id) != 0) return -1;
    dns->id = htons(internal_id);

    // Store mapping
    ctx->qmap[internal_id].in_use = 1;
    ctx->qmap[internal_id].internal_id = internal_id;
    ctx->qmap[internal_id].original_id = original_id;
    ctx->qmap[internal_id].client_addr = *client_addr;
    ctx->qmap[internal_id].client_len = client_len;
    ctx->qmap[internal_id].backend_index = backend_index;
    ctx->qmap[internal_id].timestamp_ms = now_ms();

    // Send to backend
    ssize_t sent;
    if (b->connected) {
        sent = send(b->fd, query, (size_t)query_len, MSG_DONTWAIT);
    } else {
        sent = sendto(b->fd, query, (size_t)query_len, MSG_DONTWAIT, (struct sockaddr*)&b->addr, sizeof(b->addr));
    }
    if (sent != query_len) {
        ctx->qmap[internal_id].in_use = 0;
        return -1;
    }
    return 0;
}

// Optimized DNS server main loop with high-performance batching
void dns_server_loop_fd(int sockfd, struct backend_manager *bm) {
    // Pre-allocate all buffers to avoid malloc/free in hot path
    static unsigned char buffer[BUFFER_SIZE];
    static struct epoll_event ev, events[128]; // Increased event buffer
    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); exit(1); }

    struct worker_ctx ctx_local;
    memset(&ctx_local, 0, sizeof(ctx_local));
    ctx_local.sockfd = sockfd;
    ctx_local.bm = bm;
    setup_backend_sockets_worker(&ctx_local);

    // Add client socket
    ev.events = EPOLLIN | EPOLLET; // Edge-triggered for better performance
    ev.data.fd = sockfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) { perror("epoll_ctl client"); exit(1); }

    // Add backend sockets
    for (int i = 0; i < ctx_local.backend_count; ++i) {
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = ctx_local.backends[i].fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, ctx_local.backends[i].fd, &ev) < 0) { perror("epoll_ctl backend"); exit(1); }
    }

    if (g_verbose) printf("DNS worker event loop started on fd %d\n", sockfd);

    // Optimized batch sizes for maximum throughput (macros at file scope)
    
    // Pre-allocate all message structures
    static struct mmsghdr msgs[BATCH_SZ];
    static struct iovec iovecs[BATCH_SZ];
    static unsigned char batch_buf[BATCH_SZ][BUFFER_SIZE];
    static struct sockaddr_in client_addrs[BATCH_SZ];
    
    // Pre-allocate response structures
    static struct mmsghdr out_msgs[BATCH_SZ];
    static struct iovec out_iov[BATCH_SZ];
    static struct sockaddr_in out_addrs[BATCH_SZ];
    
    // Pre-allocate backend response structures
    static struct mmsghdr backend_msgs[MAX_BACKEND_BATCH];
    static struct iovec backend_iov[MAX_BACKEND_BATCH];
    static unsigned char backend_buf[MAX_BACKEND_BATCH][BUFFER_SIZE];
    
    // Initialize once
    memset(msgs, 0, sizeof(msgs));
    memset(iovecs, 0, sizeof(iovecs));
    memset(backend_msgs, 0, sizeof(backend_msgs));
    memset(backend_iov, 0, sizeof(backend_iov));

    // Performance counters
    uint64_t total_queries = 0;
    uint64_t cache_hits = 0;
    uint64_t last_stats_time = now_ms();

    while (running) {
        int nfds = epoll_wait(epfd, events, 128, 1); // Reduced timeout for lower latency
        for (int n = 0; n < nfds; ++n) {
            int fd = events[n].data.fd;
            if (fd == sockfd) {
                // Optimized batch receive with larger batches
                int recvd = 0;
                do {
                    // Setup batch receive
                    for (int i = 0; i < BATCH_SZ; ++i) {
                        iovecs[i].iov_base = batch_buf[i];
                        iovecs[i].iov_len = BUFFER_SIZE;
                        msgs[i].msg_hdr.msg_iov = &iovecs[i];
                        msgs[i].msg_hdr.msg_iovlen = 1;
                        msgs[i].msg_hdr.msg_name = &client_addrs[i];
                        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                    }
                    
                    recvd = recvmmsg(sockfd, msgs, BATCH_SZ, MSG_DONTWAIT, NULL);
                    if (recvd > 0) {
                        total_queries += recvd;
                        
                        // Process batch with minimal allocations
                        int out_count = 0;
                        for (int i = 0; i < recvd; ++i) {
                            if (msgs[i].msg_len < sizeof(struct dns_header)) continue;
                            
                            struct sockaddr_in *caddr = (struct sockaddr_in*)msgs[i].msg_hdr.msg_name;
                            struct dns_header *dns_hdr = (struct dns_header*)iovecs[i].iov_base;
                            
                            // Parse query and try cache (A/AAAA)
                            struct dns_parser p;
                            if (parse_dns_query(&p, (const char*)iovecs[i].iov_base, (int)msgs[i].msg_len) == 0) {
                                if (p.qclass == 1 && (p.qtype == DNS_TYPE_A || p.qtype == DNS_TYPE_AAAA)) {
                                    int cached_len = cache_lookup_and_build(&ctx_local, p.qname, p.qtype,
                                                                            ntohs(dns_hdr->id), batch_buf[i], BUFFER_SIZE);
                                    if (cached_len > 0) {
                                        cache_hits++;
                                        out_iov[out_count].iov_base = batch_buf[i];
                                        out_iov[out_count].iov_len = (size_t)cached_len;
                                        out_msgs[out_count].msg_hdr.msg_iov = &out_iov[out_count];
                                        out_msgs[out_count].msg_hdr.msg_iovlen = 1;
                                        out_addrs[out_count] = *caddr;
                                        out_msgs[out_count].msg_hdr.msg_name = &out_addrs[out_count];
                                        out_msgs[out_count].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                                        out_count++;
                                        continue;
                                    }
                                }
                            }
                            
                            // No cache hit -> forward to backend
                            if (forward_to_backend_w(&ctx_local, (unsigned char*)iovecs[i].iov_base, 
                                                   (int)msgs[i].msg_len, caddr, sizeof(*caddr)) != 0) {
                                // Send error response immediately
                                struct dns_header *err_hdr = (struct dns_header*)batch_buf[i];
                                memcpy(err_hdr, dns_hdr, sizeof(struct dns_header));
                                err_hdr->flags = htons(0x8183); // Response + Server failure
                                err_hdr->ancount = 0;
                                err_hdr->nscount = 0;
                                err_hdr->arcount = 0;
                                
                                out_iov[out_count].iov_base = batch_buf[i];
                                out_iov[out_count].iov_len = sizeof(struct dns_header);
                                out_msgs[out_count].msg_hdr.msg_iov = &out_iov[out_count];
                                out_msgs[out_count].msg_hdr.msg_iovlen = 1;
                                out_addrs[out_count] = *caddr;
                                out_msgs[out_count].msg_hdr.msg_name = &out_addrs[out_count];
                                out_msgs[out_count].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                                out_count++;
                            }
                        }
                        
                        // Send all responses in one batch
                        if (out_count > 0) {
                            sendmmsg(sockfd, out_msgs, (unsigned int)out_count, MSG_DONTWAIT);
                        }
                    }
                } while (recvd == BATCH_SZ); // Continue while we have more data
                
            } else {
                // Backend response handling with batching
                int recvd = 0;
                do {
                    // Setup backend batch receive
                    for (int i = 0; i < MAX_BACKEND_BATCH; ++i) {
                        backend_iov[i].iov_base = backend_buf[i];
                        backend_iov[i].iov_len = BUFFER_SIZE;
                        backend_msgs[i].msg_hdr.msg_iov = &backend_iov[i];
                        backend_msgs[i].msg_hdr.msg_iovlen = 1;
                    }
                    
                    recvd = recvmmsg(fd, backend_msgs, MAX_BACKEND_BATCH, MSG_DONTWAIT, NULL);
                    if (recvd > 0) {
                        int out_count = 0;
                        for (int i = 0; i < recvd; ++i) {
                            if (backend_msgs[i].msg_len < sizeof(struct dns_header)) continue;
                            
                            struct dns_header *dnsr = (struct dns_header*)backend_iov[i].iov_base;
                            uint16_t internal_id = ntohs(dnsr->id);
                            
                            // Direct slot lookup by internal_id
                            if (internal_id < MAX_PENDING_QUERIES && ctx_local.qmap[internal_id].in_use) {
                                dnsr->id = htons(ctx_local.qmap[internal_id].original_id);
                                
                                // Store cache on successful responses for A/AAAA
                                uint16_t flags = ntohs(dnsr->flags);
                                if ((flags & 0x0F) == 0 && ntohs(dnsr->ancount) > 0) {
                                    struct dns_parser resp_p;
                                    if (parse_dns_query(&resp_p, (const char*)backend_iov[i].iov_base,
                                                        (int)backend_msgs[i].msg_len) == 0) {
                                        if (resp_p.qclass == 1 && (resp_p.qtype == DNS_TYPE_A || resp_p.qtype == DNS_TYPE_AAAA)) {
                                            uint16_t saved_id = dnsr->id;
                                            dnsr->id = 0;
                                            cache_store(&ctx_local, resp_p.qname, resp_p.qtype,
                                                        (unsigned char*)backend_iov[i].iov_base,
                                                        (int)backend_msgs[i].msg_len);
                                            dnsr->id = saved_id;
                                        }
                                    }
                                }
                                
                                // Queue response to client
                                out_iov[out_count].iov_base = backend_iov[i].iov_base;
                                out_iov[out_count].iov_len = backend_msgs[i].msg_len;
                                out_msgs[out_count].msg_hdr.msg_iov = &out_iov[out_count];
                                out_msgs[out_count].msg_hdr.msg_iovlen = 1;
                                out_addrs[out_count] = ctx_local.qmap[internal_id].client_addr;
                                out_msgs[out_count].msg_hdr.msg_name = &out_addrs[out_count];
                                out_msgs[out_count].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                                backend_manager_increment_connections(bm, ctx_local.qmap[internal_id].backend_index);
                                ctx_local.qmap[internal_id].in_use = 0;
                                out_count++;
                            }
                        }
                        
                        // Send all responses in one batch
                        if (out_count > 0) {
                            sendmmsg(sockfd, out_msgs, (unsigned int)out_count, MSG_DONTWAIT);
                        }
                    }
                } while (recvd == MAX_BACKEND_BATCH);
            }
        }
        
        // Periodic cleanup and stats
        static uint64_t last_cleanup = 0;
        uint64_t now = now_ms();
        if (now - last_cleanup > 1000) { // Cleanup every second
            // Timeout old queries (2s)
            for (int i = 0; i < MAX_PENDING_QUERIES; ++i) {
                if (ctx_local.qmap[i].in_use && now - ctx_local.qmap[i].timestamp_ms > 2000) {
                    ctx_local.qmap[i].in_use = 0;
                }
            }
            last_cleanup = now;
        }
        
        // Print performance stats every 5 seconds
        if (now - last_stats_time > 5000) {
            if (g_verbose) {
                printf("Performance: %lu queries/sec, %lu cache hits/sec (%.1f%% hit rate)\n",
                       total_queries / 5, cache_hits / 5, 
                       total_queries > 0 ? (100.0 * cache_hits / total_queries) : 0.0);
            }
            total_queries = 0;
            cache_hits = 0;
            last_stats_time = now;
        }
    }
    close(epfd);
}

struct worker_args {
    int sockfd;
    struct backend_manager *bm;
};

static void* worker_thread(void* arg) {
    struct worker_args *wa = (struct worker_args*)arg;
    dns_server_loop_fd(wa->sockfd, wa->bm);
    return NULL;
}

// Simple configuration loading
int load_configuration(struct backend_manager *bm, const char *filename) {
    (void)filename; // For now, use defaults
    
    printf("Loading configuration...\n");
    
    // Use local mock backends if MOCK_BACKENDS environment variable is set
    const char *use_mock = getenv("MOCK_BACKENDS");
    if (use_mock && strcmp(use_mock, "0") != 0) {
        backend_manager_add_backend(bm, "127.0.0.1", 5353, 1, "mock1");
        backend_manager_add_backend(bm, "127.0.0.1", 5354, 1, "mock2");
    } else {
        backend_manager_add_backend(bm, "8.8.8.8", 53, 1, "google");
        backend_manager_add_backend(bm, "1.1.1.1", 53, 1, "cloudflare");
        backend_manager_add_backend(bm, "9.9.9.9", 53, 1, "quad9");
    }
    
    bm->config.algorithm = LB_ROUND_ROBIN;
    bm->config.health_check_interval = 5000;
    bm->config.max_retries = 3;
    bm->config.timeout_ms = 2000;
    
    return 0;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -c, --config FILE    Load configuration from FILE\n");
    printf("  -p, --port PORT      Listen on UDP PORT (default: 53; use >1024 when unprivileged)\n");
    printf("  -w, --workers N      Number of worker threads using SO_REUSEPORT (default: 1)\n");
    printf("  -v, --verbose        Enable verbose output (debug logs)\n");
    printf("  -h, --help           Show this help message\n");
}

int main(int argc, char *argv[]) {
    const char *config_file = CONFIG_FILE;
    int verbose = 0;
    int workers = 1;
    uint16_t listen_port = 53;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                config_file = argv[++i];
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            listen_port = (uint16_t)atoi(argv[++i]);
        } else if ((strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--workers") == 0) && i + 1 < argc) {
            workers = atoi(argv[++i]);
            if (workers < 1) workers = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    printf("DNS Load Balancer Starting...\n");
    printf("Note: This may need root to bind to low ports (e.g., 53).\n");
    
    // Check if running as root
    // Only enforce root for privileged ports
    if (listen_port < 1024 && geteuid() != 0) {
        fprintf(stderr, "Error: Must be run as root to bind to port %u\n", (unsigned)listen_port);
        fprintf(stderr, "Try: sudo %s -p %u\n", argv[0], (unsigned)listen_port);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create DNS socket
    g_verbose = verbose;
    g_listen_port = listen_port;

    // Multi-worker: each worker creates its own socket with SO_REUSEPORT
    int reuse_port = (workers > 1) ? 1 : 0;
    if (workers == 1) {
        dns_socket = create_dns_socket(listen_port, reuse_port);
        if (dns_socket < 0) {
            fprintf(stderr, "Failed to create DNS socket\n");
            return 1;
        }
    }
    
    // Initialize backend manager
    g_bm = backend_manager_init();
    if (!g_bm) {
        fprintf(stderr, "Failed to initialize backend manager\n");
        close(dns_socket);
        return 1;
    }
    
    // Load configuration
    if (load_configuration(g_bm, config_file) != 0) {
        fprintf(stderr, "Failed to load configuration\n");
        backend_manager_cleanup(g_bm);
        close(dns_socket);
        return 1;
    }
    
    /*// Start health checker
    if (health_checker_init(g_bm->config.health_check_interval) != 0) {
        fprintf(stderr, "Failed to start health checker\n");
        backend_manager_cleanup(g_bm);
        close(dns_socket);
        return 1;
    }*/
    
    printf("DNS Load Balancer is running on port %u with %d worker(s)\n", (unsigned)listen_port, workers);
    printf("Backends configured:\n");
    backend_manager_print_status(g_bm);
    
    // Run DNS server loop(s)
    if (workers == 1) {
        dns_server_loop_fd(dns_socket, g_bm);
    } else {
        pthread_t *tids = calloc((size_t)workers, sizeof(pthread_t));
        struct worker_args *args = calloc((size_t)workers, sizeof(struct worker_args));
        if (!tids || !args) {
            fprintf(stderr, "Allocation failure for workers\n");
            return 1;
        }
        for (int i = 0; i < workers; i++) {
            int s = create_dns_socket(listen_port, 1);
            if (s < 0) {
                fprintf(stderr, "Failed to create worker socket %d\n", i);
                running = 0;
                break;
            }
            args[i].sockfd = s;
            args[i].bm = g_bm;
            if (pthread_create(&tids[i], NULL, worker_thread, &args[i]) != 0) {
                perror("pthread_create");
                running = 0;
                break;
            }
        }
        for (int i = 0; i < workers; i++) {
            if (tids[i]) pthread_join(tids[i], NULL);
        }
        free(tids);
        free(args);
    }
    
    printf("Shutting down...\n");
    
    // Cleanup
    health_checker_stop();
    backend_manager_cleanup(g_bm);
    if (dns_socket >= 0) close(dns_socket);
    
    printf("DNS Load Balancer stopped.\n");
    return 0;
}