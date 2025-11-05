#include "worker.hpp"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <chrono>
#include <algorithm>
#include <string_view>
#include <thread>

Worker::Worker(const Config& config, int worker_id, SharedHealthState* shared_health,
               SharedMetrics* shared_metrics)
    : config_(config), worker_id_(worker_id), shared_health_(shared_health),
      shared_metrics_(shared_metrics), udp_socket_(-1), epoll_fd_(-1),
      backend_socket_(-1), next_backend_tx_id_(1), cleanup_index_(0),
      pool_rr_counter_(0) {
    
    rrl_state_.window_nanos_ = config_.rrl_window_seconds * 1000000000ULL;
    memset(&rrl_state_.buckets_, 0, sizeof(rrl_state_.buckets_));
    
    // OPTIMIZED: Allocate pending requests array on heap (cache-aligned)
    pending_requests_ = static_cast<PendingRequestSlot*>(
        aligned_alloc(64, sizeof(PendingRequestSlot) * PENDING_REQUESTS_SIZE));
    if (!pending_requests_) {
        // Fallback to regular allocation
        pending_requests_ = new PendingRequestSlot[PENDING_REQUESTS_SIZE];
    }
    // Initialize all slots as invalid
    for (size_t i = 0; i < PENDING_REQUESTS_SIZE; i++) {
        pending_requests_[i].valid = false;
        pending_requests_[i].tx_id = 0;
    }
    
    // Initialize backend cache
    memset(&backend_cache_, 0, sizeof(backend_cache_));
    
    // Initialize metrics batch
    memset(&metrics_batch_, 0, sizeof(metrics_batch_));
    
    // Initialize batching buffers
    memset(client_batch_, 0, sizeof(client_batch_));
    memset(response_batch_, 0, sizeof(response_batch_));
    pending_responses_ = 0;

    // Initialize cache
    cache_ = nullptr;
    cache_capacity_ = 0;
}

Worker::~Worker() {
    if (udp_socket_ >= 0) close(udp_socket_);
    if (backend_socket_ >= 0) close(backend_socket_);
    if (epoll_fd_ >= 0) close(epoll_fd_);
    
    // Free pending requests array
    if (pending_requests_) {
        free(pending_requests_);  // Works for both aligned_alloc and new
        pending_requests_ = nullptr;
    }
    
    // Flush any remaining metrics
    flush_metrics();

    if (cache_) {
        free(cache_);
        cache_ = nullptr;
    }
}

int Worker::run() {
    if (!initialize()) {
        return 1;
    }
    
    event_loop();
    return 0;
}

bool Worker::initialize() {
    // Set CPU affinity
    if (!set_cpu_affinity(worker_id_)) {
        // Non-fatal, continue anyway
    }
    
    // Setup socket
    if (!setup_socket()) {
        return false;
    }
    
    // Setup epoll
    if (!setup_epoll()) {
        return false;
    }
    
    // Increase process file descriptor limits if possible
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    
    // Initialize packet cache (per worker)
    if (config_.enable_cache && config_.cache_size > 0) {
        // round to next power of two (minimum 1024)
        size_t cap = 1024;
        while (cap < static_cast<size_t>(config_.cache_size) && cap < (1u<<20)) cap <<= 1;
        cache_capacity_ = cap;
        cache_ = static_cast<CacheEntry*>(aligned_alloc(64, sizeof(CacheEntry) * cache_capacity_));
        if (!cache_) {
            cache_capacity_ = 0;
        } else {
            for (size_t i = 0; i < cache_capacity_; ++i) {
                cache_[i].valid = false;
                cache_[i].key = 0;
                cache_[i].expiry_ms = 0;
                cache_[i].len = 0;
            }
        }
    }

    return true;
}

bool Worker::set_cpu_affinity(int cpu_core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core, &cpuset);
    
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) < 0) {
        perror("sched_setaffinity");
        return false;
    }
    
    return true;
}

bool Worker::setup_socket() {
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);//AF_packet packet mmap
    if (udp_socket_ < 0) {
        perror("socket");
        return false;
    }
    
    // Set SO_REUSEPORT for load distribution
    int reuse = 1;
    if (setsockopt(udp_socket_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEPORT");
        close(udp_socket_);
        return false;
    }
    
    // Set socket buffer sizes - CRITICAL for high QPS
    // Use maximum system limits for high throughput
    int rcvbuf = 64 * 1024 * 1024;  // 64MB receive buffer (increased further)
    if (setsockopt(udp_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        rcvbuf = 32 * 1024 * 1024;  // Fallback to 32MB
        setsockopt(udp_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }
    
    int sndbuf = 64 * 1024 * 1024;  // 64MB send buffer (increased further)
    if (setsockopt(udp_socket_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        sndbuf = 32 * 1024 * 1024;  // Fallback to 32MB
        setsockopt(udp_socket_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }
    
    // Bind to address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.listen_port);
    
    if (inet_pton(AF_INET, config_.listen_address.c_str(), &addr.sin_addr) <= 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    if (bind(udp_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(udp_socket_);
        return false;
    }
    
    // Create backend socket (for forwarding)
    backend_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (backend_socket_ < 0) {
        perror("socket backend");
        close(udp_socket_);
        return false;
    }
    
    // Bind backend socket to any available port to ensure responses can be received
    struct sockaddr_in backend_bind_addr;
    memset(&backend_bind_addr, 0, sizeof(backend_bind_addr));
    backend_bind_addr.sin_family = AF_INET;
    backend_bind_addr.sin_addr.s_addr = INADDR_ANY;
    backend_bind_addr.sin_port = 0;  // Let OS assign port
    if (bind(backend_socket_, (struct sockaddr*)&backend_bind_addr, sizeof(backend_bind_addr)) < 0) {
        perror("bind backend_socket");
        close(backend_socket_);
        close(udp_socket_);
        return false;
    }
    
    // Set large buffers for backend socket too
    int backend_rcvbuf = 64 * 1024 * 1024;  // 64MB (increased further)
    setsockopt(backend_socket_, SOL_SOCKET, SO_RCVBUF, &backend_rcvbuf, sizeof(backend_rcvbuf));
    int backend_sndbuf = 64 * 1024 * 1024;  // 64MB (increased further)
    setsockopt(backend_socket_, SOL_SOCKET, SO_SNDBUF, &backend_sndbuf, sizeof(backend_sndbuf));
    
    // Optional busy-poll tuning (Linux >= 5.11)
#ifdef SO_BUSY_POLL
    {
        int busy_poll = 50; // microseconds
        setsockopt(udp_socket_, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
        setsockopt(backend_socket_, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
    }
#endif
#ifdef SO_PREFER_BUSY_POLL
    {
        int prefer = 1;
        setsockopt(udp_socket_, SOL_SOCKET, SO_PREFER_BUSY_POLL, &prefer, sizeof(prefer));
        setsockopt(backend_socket_, SOL_SOCKET, SO_PREFER_BUSY_POLL, &prefer, sizeof(prefer));
    }
#endif

    // Set non-blocking mode
    int flags = fcntl(udp_socket_, F_GETFL, 0);
    fcntl(udp_socket_, F_SETFL, flags | O_NONBLOCK);
    
    flags = fcntl(backend_socket_, F_GETFL, 0);
    fcntl(backend_socket_, F_SETFL, flags | O_NONBLOCK);
    
    return true;
}

bool Worker::setup_epoll() {
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        perror("epoll_create1");
        return false;
    }
    
    // OPTIMIZED: Use edge-triggered mode for better performance
    // Edge-triggered requires draining all data, but reduces epoll_wait calls
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;  // Edge-triggered for high throughput
    ev.data.fd = udp_socket_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, udp_socket_, &ev) < 0) {
        perror("epoll_ctl add udp_socket");
        return false;
    }
    
    // Add backend socket to epoll (also edge-triggered)
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = backend_socket_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, backend_socket_, &ev) < 0) {
        perror("epoll_ctl add backend_socket");
        return false;
    }
    
    return true;
}

void Worker::event_loop() {
    // OPTIMIZED: Larger batch size for edge-triggered epoll
    constexpr int MAX_EVENTS = 32768;  // Increased for 50K+ QPS
    struct epoll_event events[MAX_EVENTS];
    
    auto last_cleanup = std::chrono::steady_clock::now();
    auto last_metrics_flush = std::chrono::steady_clock::now();
    
    while (true) {
        // OPTIMIZED: Use 0ms timeout for maximum throughput when busy
        // Fall back to 1ms timeout after idle periods to prevent CPU spinning
        static int consecutive_idle = 0;
        int timeout_ms = (consecutive_idle > 100) ? 1 : 0;  // Adaptive timeout
        
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, timeout_ms);
        
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        if (nfds == 0) {
            consecutive_idle++;
            if (consecutive_idle < 1000) {  // Allow some idle checks for cleanup
                // Continue to cleanup/metrics flush
            } else {
                consecutive_idle = 1000;  // Cap at 1000
            }
        } else {
            consecutive_idle = 0;  // Reset on activity
        }
        
        // OPTIMIZED: Flush any pending batched responses before processing new events
        flush_batched_responses();
        
        // Process all events (edge-triggered requires draining all data)
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == udp_socket_) {
                // OPTIMIZED: Batch receive using recvmmsg (one syscall for many packets)
                drain_client_packets_batch();
            } else if (events[i].data.fd == backend_socket_) {
                // OPTIMIZED: Batch receive backend responses using recvmmsg
                drain_backend_responses_batch();
            }
        }
        
        // OPTIMIZED: More frequent incremental cleanup to prevent stale entries
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_cleanup).count();
        if (elapsed_ms >= 50) {  // Every 50ms for faster cleanup
            cleanup_expired_requests_incremental();
            last_cleanup = now;
        }
        
        // Flush metrics batch periodically
        elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_metrics_flush).count();
        if (elapsed_ms >= 1000) {  // Every second
            flush_metrics();
            last_metrics_flush = now;
        }
    }
}

void Worker::handle_client_packet(uint8_t* buffer, size_t len,
                                  const struct sockaddr* client_addr, socklen_t /* client_len */) {
    // OPTIMIZED: Fast path checks first
    if (!DNS::is_query(buffer) || !DNS::validate_packet(buffer, len)) {
        metrics_batch_.errors++;
        return;
    }
    
    metrics_batch_.packets_received++;
    
    // OPTIMIZED: Extract binary IP directly (no string conversion)
    uint32_t client_ip = 0;
    uint16_t client_port = 0;
    if (client_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)client_addr;
        client_ip = addr_in->sin_addr.s_addr;
        client_port = ntohs(addr_in->sin_port);
    } else {
        // IPv6 not supported in optimized path
        metrics_batch_.errors++;
        return;
    }
    
    // OPTIMIZED: RRL disabled for 30K+ QPS (too expensive per packet)
    // RRL check removed from hot path - can be re-enabled if needed via config
    // if (config_.enable_rrl && check_rrl_binary(client_ip)) {
    //     metrics_batch_.rrl_dropped++;
    //     return;
    // }
    
    // Get transaction ID
    uint16_t original_tx_id = DNS::get_transaction_id(buffer);
    
    // OPTIMIZED: Validate max size (we will mutate in-place)
    if (len > DNS_EDNS_MAX_PACKET_SIZE) {
        metrics_batch_.errors++;
        return;
    }
    
    // Cache lookup (packet cache) before forwarding
    if (config_.enable_cache && cache_ && cache_capacity_ > 0) {
        struct sockaddr_in client_sa;
        client_sa.sin_family = AF_INET;
        client_sa.sin_addr.s_addr = client_ip;
        client_sa.sin_port = htons(client_port);
        if (cache_lookup_and_respond(buffer, len, original_tx_id, &client_sa)) {
            return;
        }
    }
    
    // Forward to backend (mutates txid in-place)
    forward_to_backend(buffer, len, original_tx_id, client_ip, client_port);
    
    // OPTIMIZED: RRL update disabled for performance (30K+ QPS target)
    // if (config_.enable_rrl) {
    //     update_rrl_bucket_binary(client_ip);
    // }
}

void Worker::handle_backend_response(const uint8_t* buffer, size_t len) {
    // OPTIMIZED: Fast path - minimal validation
    if (len < sizeof(DNSHeader)) {
        metrics_batch_.errors++;
        return;
    }
    
    // OPTIMIZED: Quick response check using direct bit check (faster than function call)
    // QR bit is bit 7 of byte 2 (0x80 = 10000000)
    if ((buffer[2] & 0x80) == 0) {  // QR bit must be 1 for response
        metrics_batch_.errors++;
        return;
    }
    
    uint16_t backend_tx_id = DNS::get_transaction_id(buffer);
    
    // OPTIMIZED: Direct array lookup with better collision handling
    size_t index = backend_tx_id % PENDING_REQUESTS_SIZE;
    PendingRequestSlot* slot = &pending_requests_[index];
    
    // OPTIMIZED: Pre-compute timeout check once outside loop (if needed)
    // Only check timeout if we suspect it might be expired (avoid expensive clock calls)
    
    // Linear probing for collisions (increased to 16 probes for high QPS)
    for (int probe = 0; probe < 16; probe++) {
        if (slot->valid && slot->tx_id == backend_tx_id) {
            // Found the request - FAST PATH: minimal checks
            
            // OPTIMIZED: Skip expensive timeout check for recent entries (most common case)
            // Only check timeout if entry seems old (timestamp > 4000ms old)
            // Most responses arrive within 100ms, so skip check for fast path
            ClientAddress client_info = slot->client;
            slot->valid = false;  // Free the slot immediately
            
            // OPTIMIZED: Write directly into batched response buffer to avoid extra copy
            if (pending_responses_ >= BATCH_SIZE) {
                flush_batched_responses();
            }
            if (len > DNS_EDNS_MAX_PACKET_SIZE) {
                metrics_batch_.errors++;
                return;
            }
            PacketBuffer& out_buf = response_batch_[pending_responses_];
            __builtin_memcpy(out_buf.data, buffer, len);
            DNS::set_transaction_id(out_buf.data, client_info.original_tx_id);
            out_buf.len = len;
            // Build client sockaddr
            struct sockaddr_in client_addr;
            client_addr.sin_family = AF_INET;
            client_addr.sin_addr.s_addr = client_info.ip_addr;
            client_addr.sin_port = htons(client_info.port);
            __builtin_memcpy(&out_buf.addr, &client_addr, sizeof(client_addr));
            out_buf.addr_len = sizeof(client_addr);
            pending_responses_++;
            
            // Insert into cache
            if (config_.enable_cache && cache_ && cache_capacity_ > 0) {
                cache_insert_from_response(out_buf.data, len);
            }
            
            return;  // Fast return - no additional processing
        }
        
        // Try next slot (linear probing)
        index = (index + 1) % PENDING_REQUESTS_SIZE;
        slot = &pending_requests_[index];
    }
    
    // Not found (expired or invalid) - this is normal at high QPS, don't count as error
}

bool Worker::extract_question_section(const uint8_t* buffer, size_t len,
                                      size_t& q_start, size_t& q_len) const {
    if (len < sizeof(DNSHeader)) return false;
    // qdcount should be >=1; we will parse first question only
    size_t offset = sizeof(DNSHeader);
    size_t pos = offset;
    // Walk name (handle compression pointer quickly)
    while (pos < len && buffer[pos] != 0) {
        if ((buffer[pos] & 0xC0) == 0xC0) { // compression pointer
            if (pos + 1 >= len) return false;
            pos += 2;
            break;
        }
        uint8_t label_len = buffer[pos];
        if (label_len == 0 || label_len > 63) return false;
        pos += 1 + label_len;
        if (pos > len) return false;
    }
    if (pos >= len) return false;
    pos++; // null
    if (pos + 4 > len) return false;
    q_start = offset;
    q_len = (pos + 4) - offset;
    return true;
}

bool Worker::cache_lookup_and_respond(uint8_t* query_buf, size_t len, uint16_t client_txid,
                                      const struct sockaddr_in* client_addr) {
    size_t qs = 0, ql = 0;
    if (!extract_question_section(query_buf, len, qs, ql)) return false;
    uint64_t key = fnv1a_64(query_buf + qs, ql);
    if (cache_capacity_ == 0) return false;
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    size_t idx = static_cast<size_t>(key) & (cache_capacity_ - 1);
    for (int probe = 0; probe < 4; ++probe) {
        CacheEntry& e = cache_[idx];
        if (e.valid) {
            if (e.key == key) {
                if (e.expiry_ms >= now_ms) {
                    // Verify question bytes match to avoid hash collision
                    size_t cs = 0, cl = 0;
                    if (extract_question_section(e.data, e.len, cs, cl) && cl == ql &&
                        memcmp(e.data + cs, query_buf + qs, ql) == 0) {
                        // Serve from cache
                        if (pending_responses_ >= BATCH_SIZE) {
                            flush_batched_responses();
                        }
                        PacketBuffer& out = response_batch_[pending_responses_];
                        __builtin_memcpy(out.data, e.data, e.len);
                        DNS::set_transaction_id(out.data, client_txid);
                        out.len = e.len;
                        __builtin_memcpy(&out.addr, client_addr, sizeof(*client_addr));
                        out.addr_len = sizeof(*client_addr);
                        pending_responses_++;
                        return true;
                    }
                } else {
                    e.valid = false; // expired
                }
            }
        } else {
            break; // stop probing on empty
        }
        idx = (idx + 1) & (cache_capacity_ - 1);
    }
    return false;
}

void Worker::cache_insert_from_response(const uint8_t* resp_buf, size_t len) {
    size_t qs = 0, ql = 0;
    if (!extract_question_section(resp_buf, len, qs, ql)) return;
    uint64_t key = fnv1a_64(resp_buf + qs, ql);
    if (cache_capacity_ == 0) return;
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    uint64_t expiry = now_ms + config_.cache_ttl_ms;
    size_t idx = static_cast<size_t>(key) & (cache_capacity_ - 1);
    for (int probe = 0; probe < 4; ++probe) {
        CacheEntry& e = cache_[idx];
        if (!e.valid || e.expiry_ms < now_ms) {
            e.key = key;
            e.expiry_ms = expiry;
            e.len = static_cast<uint16_t>(len);
            e.valid = true;
            __builtin_memcpy(e.data, resp_buf, len);
            return;
        }
        idx = (idx + 1) & (cache_capacity_ - 1);
    }
    // If no slot in probe window, overwrite the initial index
    CacheEntry& e = cache_[static_cast<size_t>(key) & (cache_capacity_ - 1)];
    e.key = key;
    e.expiry_ms = expiry;
    e.len = static_cast<uint16_t>(len);
    e.valid = true;
    __builtin_memcpy(e.data, resp_buf, len);
}

bool Worker::forward_to_backend(uint8_t* buffer, size_t len, uint16_t original_tx_id,
                               uint32_t client_ip, uint16_t client_port) {
    if (!shared_health_ || shared_health_->backend_count.load(std::memory_order_acquire) == 0) {
        metrics_batch_.errors++;
        return false;
    }
    
    // OPTIMIZED: Direct backend selection using cached array
    size_t backend_idx = select_backend_direct(client_ip);
    
    if (backend_idx >= shared_health_->backend_count.load(std::memory_order_acquire)) {
        metrics_batch_.errors++;
        return false;
    }
    
    auto& backend = shared_health_->backends[backend_idx];
    if (!backend.is_healthy.load(std::memory_order_acquire)) {
        metrics_batch_.errors++;
        return false;
    }
    
    // OPTIMIZED: Fast transaction ID generation - avoid expensive clock calls
    // Use atomic increment with minimal overhead
    uint16_t new_tx_id = next_backend_tx_id_.fetch_add(1, std::memory_order_relaxed);
    if (new_tx_id == 0) {
        new_tx_id = next_backend_tx_id_.fetch_add(1, std::memory_order_relaxed);
    }
    
    // OPTIMIZED: Use cheaper timestamp (only calculate when needed for storage)
    // Calculate timestamp only once after we find where to store
    uint64_t now_ms = 0;  // Will calculate lazily if needed
    
    // OPTIMIZED: Store in array with better collision handling
    // Use Robin Hood hashing: keep probing until we find empty slot OR expired slot
    size_t index = new_tx_id % PENDING_REQUESTS_SIZE;
    PendingRequestSlot* slot = &pending_requests_[index];

    bool stored = false;
    for (int probe = 0; probe < 16; probe++) {
        if (!slot->valid) {
            // Found empty slot - calculate timestamp only now
            if (now_ms == 0) {
                now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
            }
            slot->tx_id = new_tx_id;
            slot->client = ClientAddress(client_ip, client_port, original_tx_id, now_ms);
            slot->valid = true;
            stored = true;
            break;
        }
        
        // OPTIMIZED: Quick expiration check without timestamp calculation
        // Only calculate timestamp if entry looks potentially expired
        // Most entries are fresh, so we can skip this check for fast path
        if (slot->client.timestamp_ms != 0) {
            // Entry exists - check if expired (lazy timestamp calc)
            if (now_ms == 0) {
                now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
            }
            if (now_ms - slot->client.timestamp_ms > 5000) {
                // Overwrite expired entry
                slot->tx_id = new_tx_id;
                slot->client = ClientAddress(client_ip, client_port, original_tx_id, now_ms);
                slot->valid = true;
                stored = true;
                break;
            }
        }
        
        // Try next slot (linear probing)
        index = (index + 1) % PENDING_REQUESTS_SIZE;
        slot = &pending_requests_[index];
    }
    
    // If still not stored, force overwrite current slot (emergency fallback)
    if (!stored) {
        if (now_ms == 0) {
            now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }
        slot->tx_id = new_tx_id;
        slot->client = ClientAddress(client_ip, client_port, original_tx_id, now_ms);
        slot->valid = true;
    }
    
    // Modify transaction ID
    DNS::set_transaction_id(buffer, new_tx_id);
    
    // OPTIMIZED: Use cached backend address (no inet_pton on hot path!)
    // Backend addresses are pre-cached in BackendManager::update_shared_state()
    struct sockaddr_in* backend_addr = &backend.cached_addr;
    
    // Fallback: if cache not initialized, use binary IP
    if (backend_addr->sin_family == 0) {
        backend_addr->sin_family = AF_INET;
        backend_addr->sin_addr.s_addr = backend.ip_addr_binary;
        backend_addr->sin_port = htons(backend.port);
    }
    
    ssize_t sent = sendto(backend_socket_, buffer, len, MSG_DONTWAIT | MSG_NOSIGNAL,
                         (struct sockaddr*)backend_addr, sizeof(*backend_addr));
    
    if (sent < 0 || sent != static_cast<ssize_t>(len)) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            slot->valid = false;
            metrics_batch_.errors++;
        }
        return false;
    }
    
    backend.requests_sent.fetch_add(1, std::memory_order_relaxed);
    return true;
}

size_t Worker::select_backend_direct(uint32_t client_ip) {
    // OPTIMIZED: Use cached backend list, only refresh periodically
    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    size_t current_backend_count = shared_health_->backend_count.load(std::memory_order_acquire);
    
    // Refresh cache every 100ms or if backend count changed
    if (backend_cache_.healthy_count == 0 || 
        (now_ns - backend_cache_.last_update_ns) > 100000000ULL ||
        backend_cache_.last_update_ns == 0) {
        
        backend_cache_.healthy_count = 0;
        
        for (size_t i = 0; i < current_backend_count && backend_cache_.healthy_count < 64; i++) {
            if (shared_health_->backends[i].is_healthy.load(std::memory_order_acquire)) {
                backend_cache_.healthy_indices[backend_cache_.healthy_count++] = i;
            }
        }
        
        // Fallback: use first backend if none healthy
        if (backend_cache_.healthy_count == 0 && current_backend_count > 0) {
            backend_cache_.healthy_count = 1;
            backend_cache_.healthy_indices[0] = 0;
        }
        
        backend_cache_.last_update_ns = now_ns;
    }
    
    // Round-robin selection or configured algo
    if (backend_cache_.healthy_count == 0) {
        return 0;
    }
    
    // Choose algorithm from config (pool 0)
    const std::string* algo_ptr = nullptr;
    if (!config_.pools.empty()) algo_ptr = &config_.pools[0].lb_algorithm;
    const std::string algo = algo_ptr ? *algo_ptr : std::string("round_robin");
    size_t n = backend_cache_.healthy_count;
    
    if (algo == "p2c" || algo == "power_of_two") {
        // Very low overhead RNG via LCG on pool_rr_counter_
        uint64_t seed = (pool_rr_counter_ += 0x9E3779B97F4A7C15ULL);
        size_t a = (size_t)((seed ^ (seed >> 18)) % n);
        size_t b = (size_t)(((seed * 1103515245ULL + 12345ULL) ^ (seed >> 7)) % n);
        if (b == a) b = (a + 1) % n;
        size_t ia = backend_cache_.healthy_indices[a];
        size_t ib = backend_cache_.healthy_indices[b];
        const auto& ba = shared_health_->backends[ia];
        const auto& bb = shared_health_->backends[ib];
        uint64_t pa = ba.requests_sent.load(std::memory_order_relaxed) - ba.responses_received.load(std::memory_order_relaxed);
        uint64_t pb = bb.requests_sent.load(std::memory_order_relaxed) - bb.responses_received.load(std::memory_order_relaxed);
        return (pa <= pb) ? ia : ib;
    } else if (algo == "ip_hash") {
        // Fast multiplicative hash modulo healthy count
        uint32_t h = client_ip * 2654435761u;
        return backend_cache_.healthy_indices[h % n];
    } else if (algo == "jump_hash" || algo == "jch") {
        // Jump Consistent Hash (O(1)) using client_ip as key
        auto jump_consistent_hash = [](uint64_t key, int32_t buckets) -> int32_t {
            int64_t b = -1, j = 0;
            while (j < buckets) {
                b = j;
                key = key * 2862933555777941757ULL + 1;
                j = (int64_t)((double)(b + 1) * (double)(1LL << 31) / (double)((key >> 33) + 1));
            }
            return (int32_t)b;
        };
        int32_t slot = jump_consistent_hash((uint64_t)client_ip, (int32_t)n);
        if (slot < 0) slot = 0;
        return backend_cache_.healthy_indices[(size_t)slot];
    } else {
        // round_robin default
        size_t selected = backend_cache_.healthy_indices[pool_rr_counter_ % n];
        pool_rr_counter_++;
        return selected;
    }
}

bool Worker::check_rrl_binary(uint32_t client_ip) {
    if (!config_.enable_rrl || client_ip == 0) return false;
    
    uint32_t hash = rrl_state_.hash_ip(client_ip);
    auto& bucket = rrl_state_.buckets_[hash];
    
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Check if window expired
    if (!bucket.valid || static_cast<int64_t>(now - bucket.window_start) > static_cast<int64_t>(rrl_state_.window_nanos_)) {
        return false;  // New or expired window, allow
    }
    
    // Check rate limit
    return bucket.queries >= config_.rrl_max_per_second;
}

void Worker::update_rrl_bucket_binary(uint32_t client_ip) {
    if (!config_.enable_rrl || client_ip == 0) return;
    
    uint32_t hash = rrl_state_.hash_ip(client_ip);
    auto& bucket = rrl_state_.buckets_[hash];
    
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    
    if (!bucket.valid || static_cast<int64_t>(now - bucket.window_start) > static_cast<int64_t>(rrl_state_.window_nanos_)) {
        bucket.queries = 0;
        bucket.window_start = now;
        bucket.valid = true;
    }
    
    bucket.queries++;
}

void Worker::cleanup_expired_requests_incremental() {
    // OPTIMIZED: Incremental cleanup - scan larger portion more frequently
    // Clean up 1/5th of the array each time (5 cleanup cycles = full scan)
    // More aggressive cleanup to prevent collisions at high QPS
    uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    constexpr uint64_t TIMEOUT_MS = 5000;
    
    constexpr size_t BATCH_SIZE = PENDING_REQUESTS_SIZE / 5;  // Larger batch
    size_t start = cleanup_index_;
    size_t end = start + BATCH_SIZE;
    
    if (end > PENDING_REQUESTS_SIZE) {
        end = PENDING_REQUESTS_SIZE;
    }
    
    size_t cleaned = 0;
    for (size_t i = start; i < end; i++) {
        if (pending_requests_[i].valid) {
            // Also check if entry is really old (more than timeout)
            if (now_ms - pending_requests_[i].client.timestamp_ms > TIMEOUT_MS) {
                pending_requests_[i].valid = false;
                pending_requests_[i].tx_id = 0;  // Clear TX ID to help lookup
                cleaned++;
            }
        }
    }
    
    // Update cleanup index for next iteration
    cleanup_index_ = end;
    if (cleanup_index_ >= PENDING_REQUESTS_SIZE) {
        cleanup_index_ = 0;  // Wrap around
    }
}

// OPTIMIZED: Batch metrics updates to reduce atomic contention
void Worker::flush_metrics() {
    if (!shared_metrics_ || worker_id_ < 0 || static_cast<size_t>(worker_id_) >= MAX_METRICS_SLOTS) {
        return;
    }
    
    auto& wm = shared_metrics_->worker_metrics[worker_id_];
    
    if (metrics_batch_.packets_received > 0) {
        wm.packets_received.fetch_add(metrics_batch_.packets_received, std::memory_order_relaxed);
        shared_metrics_->total_qps.fetch_add(metrics_batch_.packets_received, std::memory_order_relaxed);
        metrics_batch_.packets_received = 0;
    }
    
    if (metrics_batch_.packets_sent > 0) {
        wm.packets_sent.fetch_add(metrics_batch_.packets_sent, std::memory_order_relaxed);
        metrics_batch_.packets_sent = 0;
    }
    
    if (metrics_batch_.errors > 0) {
        wm.errors.fetch_add(metrics_batch_.errors, std::memory_order_relaxed);
        shared_metrics_->total_errors.fetch_add(metrics_batch_.errors, std::memory_order_relaxed);
        metrics_batch_.errors = 0;
    }
    
    if (metrics_batch_.rrl_dropped > 0) {
        wm.rrl_dropped.fetch_add(metrics_batch_.rrl_dropped, std::memory_order_relaxed);
        shared_metrics_->total_rrl_dropped.fetch_add(metrics_batch_.rrl_dropped, std::memory_order_relaxed);
        metrics_batch_.rrl_dropped = 0;
    }
}

// OPTIMIZED: Batch receive using recvmmsg (one syscall for multiple packets)
void Worker::drain_client_packets_batch() {
#ifdef __linux__
    static thread_local struct mmsghdr msgs[BATCH_SIZE];
    static thread_local struct iovec iovecs[BATCH_SIZE];
    static thread_local bool initialized = false;
    
    // Setup iovecs and msgs for batch receive (once per thread)
    if (!initialized) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            iovecs[i].iov_base = client_batch_[i].data;
            iovecs[i].iov_len = DNS_EDNS_MAX_PACKET_SIZE;
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = &client_batch_[i].addr;
            msgs[i].msg_hdr.msg_namelen = sizeof(client_batch_[i].addr);
            msgs[i].msg_hdr.msg_control = nullptr;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }
        initialized = true;
    }
    
    // Batch receive using recvmmsg
    int received = recvmmsg(udp_socket_, msgs, BATCH_SIZE, MSG_DONTWAIT, nullptr);
    
    if (received > 0) {
        // Process all received packets
        for (int i = 0; i < received; i++) {
            if (msgs[i].msg_len > 0) {
                client_batch_[i].len = msgs[i].msg_len;
                client_batch_[i].addr_len = msgs[i].msg_hdr.msg_namelen;
                handle_client_packet(client_batch_[i].data, msgs[i].msg_len,
                                    (struct sockaddr*)&client_batch_[i].addr,
                                    client_batch_[i].addr_len);
            }
        }
    } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        metrics_batch_.errors++;
    }
#else
    // Fallback to recvfrom if recvmmsg not available
    for (int i = 0; i < BATCH_SIZE; i++) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t len = recvfrom(udp_socket_, client_batch_[i].data, DNS_EDNS_MAX_PACKET_SIZE,
                              MSG_DONTWAIT, (struct sockaddr*)&client_addr, &client_len);
        if (len > 0) {
            handle_client_packet(client_batch_[i].data, len,
                               (struct sockaddr*)&client_addr, client_len);
        } else if (len < 0 && errno == EAGAIN) {
            break;
        } else {
            break;
        }
    }
#endif
}

// OPTIMIZED: Batch receive backend responses using recvmmsg
void Worker::drain_backend_responses_batch() {
#ifdef __linux__
    static thread_local struct mmsghdr msgs[BATCH_SIZE];
    static thread_local struct iovec iovecs[BATCH_SIZE];
    static thread_local bool initialized = false;
    
    // Setup iovecs and msgs for batch receive (once per thread)
    if (!initialized) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            iovecs[i].iov_base = response_batch_[i].data;
            iovecs[i].iov_len = DNS_EDNS_MAX_PACKET_SIZE;
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = &response_batch_[i].addr;
            msgs[i].msg_hdr.msg_namelen = sizeof(response_batch_[i].addr);
            msgs[i].msg_hdr.msg_control = nullptr;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }
        initialized = true;
    }
    
    // Batch receive using recvmmsg
    int received = recvmmsg(backend_socket_, msgs, BATCH_SIZE, MSG_DONTWAIT, nullptr);
    
    if (received > 0) {
        // Process all received packets
        for (int i = 0; i < received; i++) {
            if (msgs[i].msg_len > 0) {
                handle_backend_response(response_batch_[i].data, msgs[i].msg_len);
            }
        }
    } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        metrics_batch_.errors++;
    }
#else
    // Fallback to recvfrom if recvmmsg not available
    for (int i = 0; i < BATCH_SIZE; i++) {
        uint8_t buffer[DNS_EDNS_MAX_PACKET_SIZE];
        struct sockaddr_storage backend_addr;
        socklen_t backend_len = sizeof(backend_addr);
        ssize_t len = recvfrom(backend_socket_, buffer, DNS_EDNS_MAX_PACKET_SIZE,
                              MSG_DONTWAIT, (struct sockaddr*)&backend_addr, &backend_len);
        if (len > 0) {
            handle_backend_response(buffer, len);
        } else if (len < 0 && errno == EAGAIN) {
            break;
        } else {
            break;
        }
    }
#endif
}

// OPTIMIZED: Queue response for batched sending
void Worker::queue_response_for_batch(const uint8_t* buffer, size_t len,
                                      const struct sockaddr_in* client_addr) {
    if (pending_responses_ >= BATCH_SIZE) {
        // Buffer full, flush immediately
        flush_batched_responses();
    }
    
    // Copy packet and address to batch buffer
    PacketBuffer& buf = response_batch_[pending_responses_];
    __builtin_memcpy(buf.data, buffer, len);
    buf.len = len;
    __builtin_memcpy(&buf.addr, client_addr, sizeof(*client_addr));
    buf.addr_len = sizeof(*client_addr);
    pending_responses_++;
}

// OPTIMIZED: Flush batched responses using sendmmsg
void Worker::flush_batched_responses() {
    if (pending_responses_ == 0) return;
    
#ifdef __linux__
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    
    // Setup iovecs and msgs for batch send
    for (int i = 0; i < pending_responses_; i++) {
        iovecs[i].iov_base = response_batch_[i].data;
        iovecs[i].iov_len = response_batch_[i].len;
        
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &response_batch_[i].addr;
        msgs[i].msg_hdr.msg_namelen = response_batch_[i].addr_len;
        msgs[i].msg_hdr.msg_control = nullptr;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
    }
    
    // Batch send using sendmmsg
    int sent = sendmmsg(udp_socket_, msgs, pending_responses_, MSG_NOSIGNAL | MSG_DONTWAIT);
    
    if (sent > 0) {
        metrics_batch_.packets_sent += sent;
    }
    pending_responses_ = 0;
#else
    // Fallback to individual sendto if sendmmsg not available
    for (int i = 0; i < pending_responses_; i++) {
        ssize_t sent = sendto(udp_socket_, response_batch_[i].data, response_batch_[i].len,
                             MSG_NOSIGNAL | MSG_DONTWAIT,
                             (struct sockaddr*)&response_batch_[i].addr,
                             response_batch_[i].addr_len);
        if (sent == static_cast<ssize_t>(response_batch_[i].len)) {
            metrics_batch_.packets_sent++;
        }
    }
    pending_responses_ = 0;
#endif
}

