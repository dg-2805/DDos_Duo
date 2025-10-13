#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>

#include "dns_lb_common.h"
#include "dns_protocol.h"
#include "backend_manager.h"



extern struct backend_manager *g_bm;

// Initialize backend manager
struct backend_manager* backend_manager_init(void) {
    struct backend_manager *bm = calloc(1, sizeof(struct backend_manager));
    if (!bm) {
        return NULL;
    }

    pthread_mutex_init(&bm->lock, NULL);
    bm->running = 1;
    bm->current_backend_index = 0;

    // Initialize with default configuration
    bm->config.algorithm = LB_ROUND_ROBIN;
    bm->config.backend_count = 0;
    bm->config.health_check_interval = 5000; // 5 seconds
    bm->config.max_retries = 3;
    bm->config.timeout_ms = 2000;

    g_bm = bm;
    return bm;
}

// Cleanup backend manager
void backend_manager_cleanup(struct backend_manager *bm) {
    if (!bm) return;

    bm->running = 0;
    pthread_mutex_destroy(&bm->lock);
    free(bm);
    g_bm = NULL;
}

// Add a backend server
int backend_manager_add_backend(struct backend_manager *bm, 
                               const char *ip_str, uint16_t port,
                               uint8_t weight, const char *region) {
    if (!bm || !ip_str) return -1;

    pthread_mutex_lock(&bm->lock);

    if (bm->config.backend_count >= MAX_BACKENDS) {
        pthread_mutex_unlock(&bm->lock);
        return -1;
    }

    struct backend_server *backend = &bm->config.backends[bm->config.backend_count];
    
    // Convert IP string to binary
    if (inet_pton(AF_INET, ip_str, &backend->ip_addr) != 1) {
        pthread_mutex_unlock(&bm->lock);
        return -1;
    }

    backend->port = port;
    backend->weight = weight ? weight : 1;
    backend->healthy = 1; // Assume healthy initially
    backend->current_connections = 0;
    backend->max_connections = 1000;
    backend->latency_ms = 0;
    backend->total_queries = 0;
    backend->failed_queries = 0;

    if (region) {
        strncpy(backend->region, region, sizeof(backend->region) - 1);
        backend->region[sizeof(backend->region) - 1] = '\0';
    } else {
        strcpy(backend->region, "default");
    }

    bm->config.backend_count++;

    pthread_mutex_unlock(&bm->lock);
    return 0;
}

// Remove a backend server
int backend_manager_remove_backend(struct backend_manager *bm, const char *ip_str, uint16_t port) {
    if (!bm || !ip_str) return -1;

    pthread_mutex_lock(&bm->lock);

    for (unsigned int i = 0; i < bm->config.backend_count; i++) {
        struct backend_server *backend = &bm->config.backends[i];
        
        char backend_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &backend->ip_addr, backend_ip, sizeof(backend_ip));
        
        if (strcmp(backend_ip, ip_str) == 0 && backend->port == port) {
            // Shift remaining backends
            for (unsigned int j = i; j < bm->config.backend_count - 1; j++) {
                memcpy(&bm->config.backends[j], &bm->config.backends[j + 1], 
                       sizeof(struct backend_server));
            }
            
            bm->config.backend_count--;
            printf("Removed backend: %s:%d\n", ip_str, port);
            
            pthread_mutex_unlock(&bm->lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&bm->lock);
    return -1; // Backend not found
}

// Optimized round-robin backend selection with minimal locking
int select_backend_round_robin(struct backend_manager *bm) {
    if (!bm || bm->config.backend_count == 0) return -1;

    // Use atomic operations for better performance
    static __thread uint32_t thread_local_index = 0;
    
    // Fast path: try current index without lock
    uint32_t start_index = thread_local_index;
    int attempts = 0;
    
    do {
        struct backend_server *backend = &bm->config.backends[thread_local_index];
        
        // Quick check without lock (best effort)
        if (backend->healthy && backend->current_connections < backend->max_connections) {
            int selected = thread_local_index;
            thread_local_index = (thread_local_index + 1) % bm->config.backend_count;
            return selected;
        }

        thread_local_index = (thread_local_index + 1) % bm->config.backend_count;
        attempts++;
    } while (attempts < (int)bm->config.backend_count);

    // Fallback: if no backend found, use first available
    for (uint32_t i = 0; i < bm->config.backend_count; i++) {
        if (bm->config.backends[i].healthy) {
            return i;
        }
    }

    return -1; // No healthy backends available
}

// Weighted round-robin backend selection
int select_backend_weighted_rr(struct backend_manager *bm) {
    if (!bm || bm->config.backend_count == 0) return -1;

    pthread_mutex_lock(&bm->lock);

    static int current_weight = 0;
    static int current_index = -1;
    
    // Reset if no backends
    if (current_index >= (int)bm->config.backend_count) {
        current_index = -1;
        current_weight = 0;
    }

    int total_weight = 0;
    int healthy_count = 0;

    // Calculate total weight and count healthy backends
    for (unsigned int i = 0; i < bm->config.backend_count; i++) {
        if (bm->config.backends[i].healthy && 
            bm->config.backends[i].current_connections < bm->config.backends[i].max_connections) {
            total_weight += bm->config.backends[i].weight;
            healthy_count++;
        }
    }

    if (healthy_count == 0) {
        pthread_mutex_unlock(&bm->lock);
        return -1;
    }

    if (current_index == -1) {
        current_index = 0;
        current_weight = total_weight;
    }

    int attempts = 0;
    while (attempts < (int)bm->config.backend_count * 2) {
        struct backend_server *backend = &bm->config.backends[current_index];
        
        if (backend->healthy && 
            backend->current_connections < backend->max_connections &&
            backend->weight >= current_weight) {
            int selected = current_index;
            current_index = (current_index + 1) % bm->config.backend_count;
            if (current_index == 0) {
                current_weight--;
                if (current_weight <= 0) {
                    current_weight = total_weight;
                }
            }
            pthread_mutex_unlock(&bm->lock);
            return selected;
        }
        
        current_index = (current_index + 1) % bm->config.backend_count;
        attempts++;
    }

    pthread_mutex_unlock(&bm->lock);
    return -1;
}

// Least connections backend selection
int select_backend_least_connections(struct backend_manager *bm) {
    if (!bm || bm->config.backend_count == 0) return -1;

    pthread_mutex_lock(&bm->lock);

    int min_connections = -1;
    int selected_index = -1;

    for (unsigned int i = 0; i < bm->config.backend_count; i++) {
        struct backend_server *backend = &bm->config.backends[i];
        
        if (!backend->healthy) continue;
        if (backend->current_connections >= backend->max_connections) continue;

        if (min_connections == -1 || (int)backend->current_connections < min_connections) {
            min_connections = backend->current_connections;
            selected_index = i;
        }
    }

    pthread_mutex_unlock(&bm->lock);
    return selected_index;
}

// Latency-based backend selection
int select_backend_latency_based(struct backend_manager *bm) {
    if (!bm || bm->config.backend_count == 0) return -1;

    pthread_mutex_lock(&bm->lock);

    int min_latency = -1;
    int selected_index = -1;

    for (unsigned int i = 0; i < bm->config.backend_count; i++) {
        struct backend_server *backend = &bm->config.backends[i];
        
        if (!backend->healthy) continue;
        if (backend->current_connections >= backend->max_connections) continue;

        if (min_latency == -1 || (int)backend->latency_ms < min_latency) {
            min_latency = backend->latency_ms;
            selected_index = i;
        }
    }

    pthread_mutex_unlock(&bm->lock);
    return selected_index;
}

// Optimized main backend selection function with fast path
int backend_manager_select_backend(struct backend_manager *bm) {
    if (!bm || bm->config.backend_count == 0) return -1;

    // Fast path for round robin (most common case)
    if (bm->config.algorithm == LB_ROUND_ROBIN) {
        return select_backend_round_robin(bm);
    }

    // For other algorithms, use optimized versions
    switch (bm->config.algorithm) {
        case LB_WEIGHTED_ROUND_ROBIN:
            return select_backend_weighted_rr(bm);
        case LB_LEAST_CONNECTIONS:
            return select_backend_least_connections(bm);
        case LB_LATENCY_BASED:
            return select_backend_latency_based(bm);
        case LB_GEO_AWARE:
            // For now, fall back to round robin
            return select_backend_round_robin(bm);
        default:
            return select_backend_round_robin(bm);
    }
}

// Update backend health status
void backend_manager_update_health(struct backend_manager *bm, int backend_index, 
                                  int healthy, uint32_t latency_ms) {
    if (!bm || backend_index < 0 || (unsigned int)backend_index >= bm->config.backend_count) return;
    pthread_mutex_lock(&bm->lock);
    
    struct backend_server *backend = &bm->config.backends[backend_index];
    backend->healthy = healthy ? 1 : 0;
    if (latency_ms > 0) {
        backend->latency_ms = latency_ms;
    }

    pthread_mutex_unlock(&bm->lock);
}

// Increment connection count for a backend
void backend_manager_increment_connections(struct backend_manager *bm, int backend_index) {
    if (!bm || backend_index < 0 || (unsigned int)backend_index >= bm->config.backend_count) return;
    pthread_mutex_lock(&bm->lock);
    
    if (bm->config.backends[backend_index].current_connections < 
        bm->config.backends[backend_index].max_connections) {
        bm->config.backends[backend_index].current_connections++;
        bm->config.backends[backend_index].total_queries++;
        bm->total_queries++;
    }

    pthread_mutex_unlock(&bm->lock);
}

// Decrement connection count for a backend
void backend_manager_decrement_connections(struct backend_manager *bm, int backend_index) {
    if (!bm || backend_index < 0 || (unsigned int)backend_index >= bm->config.backend_count) return;

    pthread_mutex_lock(&bm->lock);
    
    if (bm->config.backends[backend_index].current_connections > 0) {
        bm->config.backends[backend_index].current_connections--;
    }

    pthread_mutex_unlock(&bm->lock);
}

// Record failed query for a backend
void backend_manager_record_failure(struct backend_manager *bm, int backend_index) {
    if (!bm || backend_index < 0 || (unsigned int)backend_index >= bm->config.backend_count) return;

    pthread_mutex_lock(&bm->lock);
    
    bm->config.backends[backend_index].failed_queries++;
    bm->failed_queries++;

    pthread_mutex_unlock(&bm->lock);
}

// Get backend statistics
void backend_manager_get_stats(struct backend_manager *bm, struct lb_config *config_out,
                              uint64_t *total_queries, uint64_t *failed_queries) {
    if (!bm) return;

    pthread_mutex_lock(&bm->lock);
    
    if (config_out) {
        memcpy(config_out, &bm->config, sizeof(struct lb_config));
    }
    
    if (total_queries) {
        *total_queries = bm->total_queries;
    }
    
    if (failed_queries) {
        *failed_queries = bm->failed_queries;
    }

    pthread_mutex_unlock(&bm->lock);
}

// Print backend status
void backend_manager_print_status(struct backend_manager *bm) {
    if (!bm) return;

    pthread_mutex_lock(&bm->lock);

    printf("\n=== Backend Manager Status ===\n");
    printf("Algorithm: %d\n", bm->config.algorithm);
    printf("Total Queries: %lu, Failed: %lu\n", bm->total_queries, bm->failed_queries);
    printf("Backends (%d):\n", bm->config.backend_count);

    for (unsigned int i = 0; i < bm->config.backend_count; i++) {
        struct backend_server *backend = &bm->config.backends[i];
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &backend->ip_addr, ip_str, sizeof(ip_str));

        printf("  [%d] %s:%d - %s (conn: %d/%d, latency: %dms, weight: %d, region: %s)\n",
               i, ip_str, backend->port,
               backend->healthy ? "HEALTHY" : "UNHEALTHY",
               backend->current_connections, backend->max_connections,
               backend->latency_ms, backend->weight, backend->region);
    }

    printf("==============================\n\n");
    pthread_mutex_unlock(&bm->lock);
}
