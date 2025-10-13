#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

#include "dns_lb_common.h"
#include "dns_protocol.h"
#include "backend_manager.h"  // Add this include

extern struct backend_manager *g_bm;

// Health check context
struct health_checker {
    pthread_t thread;
    int running;
    int check_interval_ms;
};

static struct health_checker g_hc;

// Perform health check for a single backend
int perform_health_check(struct backend_server *backend) {
    if (!backend) return -1;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Build DNS query for health check
    char query_buffer[512];
    struct dns_header *header = (struct dns_header*)query_buffer;
    memset(header, 0, sizeof(struct dns_header));
    
    header->id = htons(0x1234);
    header->flags = htons(0x0100); // RD flag set
    header->qdcount = htons(1);

    // Build question: google.com A record
    char *qname_ptr = query_buffer + sizeof(struct dns_header);
    const char *test_domain = "google.com";
    char *ptr = qname_ptr;
    
    // Manual domain encoding (simpler approach)
    const char *domain = test_domain;
    const char *dot = strchr(domain, '.');
    if (!dot) {
        close(sockfd);
        return 0;
    }
    
    // First label
    int len1 = dot - domain;
    *ptr++ = len1;
    memcpy(ptr, domain, len1);
    ptr += len1;
    
    // Second label  
    const char *second = dot + 1;
    int len2 = strlen(second);
    *ptr++ = len2;
    memcpy(ptr, second, len2);
    ptr += len2;
    
    *ptr++ = 0; // Null terminator
    
    // QTYPE and QCLASS
    *(uint16_t*)ptr = htons(DNS_TYPE_A);
    ptr += 2;
    *(uint16_t*)ptr = htons(1); // IN class
    ptr += 2;

    int query_len = ptr - query_buffer;

    // Send query to backend
    struct sockaddr_in backend_addr;
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_addr.s_addr = backend->ip_addr;  // FIX: Use s_addr
    backend_addr.sin_port = htons(backend->port);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    ssize_t sent = sendto(sockfd, query_buffer, query_len, 0,
                         (struct sockaddr*)&backend_addr, sizeof(backend_addr));
    if (sent != query_len) {
        close(sockfd);
        return 0; // Unhealthy
    }

    // Receive response
    char response_buffer[512];
    struct sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);
    
    ssize_t received = recvfrom(sockfd, response_buffer, sizeof(response_buffer), 0,
                               (struct sockaddr*)&response_addr, &addr_len);
    
    gettimeofday(&end, NULL);

    close(sockfd);

    if (received <= 0) {
        return 0; // Unhealthy - no response or timeout
    }

    // Calculate latency
    long latency_ms = (end.tv_sec - start.tv_sec) * 1000 +
                     (end.tv_usec - start.tv_usec) / 1000;

    // Basic response validation
    if (received < (ssize_t)sizeof(struct dns_header)) {
        return 0; // Unhealthy - response too short
    }

    struct dns_header *response_header = (struct dns_header*)response_buffer;
    if (!(ntohs(response_header->flags) & DNS_QR_RESPONSE)) {
        return 0; // Unhealthy - not a response
    }

    // Update backend latency
    backend->latency_ms = (uint32_t)latency_ms;

    return 1; // Healthy
}

// Health checker thread function
void* health_checker_thread(void *arg) {
    (void)arg; // Mark unused parameter
    
    printf("Health checker started (interval: %d ms)\n", g_hc.check_interval_ms);

    while (g_hc.running) {
        if (!g_bm) {
            usleep(g_hc.check_interval_ms * 1000);
            continue;
        }

        // Get current backend configuration
        struct lb_config config;
        backend_manager_get_stats(g_bm, &config, NULL, NULL);

        // Check each backend
        for (unsigned int i = 0; i < config.backend_count && g_hc.running; i++) {
            struct backend_server backend = config.backends[i];
            int healthy = perform_health_check(&backend);
            
            if (g_bm) {
                backend_manager_update_health(g_bm, i, healthy, backend.latency_ms);
            }

            if (!healthy) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &backend.ip_addr, ip_str, sizeof(ip_str));
                printf("Health check failed for backend %s:%d\n", ip_str, backend.port);
            }

            // Small delay between backend checks
            usleep(100000); // 100ms
        }

        // Sleep until next health check round
        usleep(g_hc.check_interval_ms * 1000);
    }

    printf("Health checker stopped\n");
    return NULL;
}

// Initialize health checker
int health_checker_init(int check_interval_ms) {
    memset(&g_hc, 0, sizeof(g_hc));
    g_hc.running = 1;
    g_hc.check_interval_ms = check_interval_ms;

    if (pthread_create(&g_hc.thread, NULL, health_checker_thread, NULL) != 0) {
        perror("pthread_create");
        return -1;
    }

    return 0;
}

// Stop health checker
void health_checker_stop(void) {
    g_hc.running = 0;
    if (g_hc.thread) {
        pthread_join(g_hc.thread, NULL);
    }
}

// Get health checker status
int health_checker_is_running(void) {
    return g_hc.running;
}
