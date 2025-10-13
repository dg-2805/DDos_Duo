#ifndef BACKEND_MANAGER_H
#define BACKEND_MANAGER_H

#include "dns_lb_common.h"
#include <pthread.h>

extern struct backend_manager *g_bm;

struct backend_manager {
    struct lb_config config;
    pthread_mutex_t lock;
    int running;
    uint64_t total_queries;
    uint64_t failed_queries;
    uint32_t current_backend_index;
};

// Function prototypes
struct backend_manager* backend_manager_init(void);
void backend_manager_cleanup(struct backend_manager *bm);
int backend_manager_add_backend(struct backend_manager *bm, 
                               const char *ip_str, uint16_t port,
                               uint8_t weight, const char *region);
int backend_manager_remove_backend(struct backend_manager *bm, const char *ip_str, uint16_t port);
int backend_manager_select_backend(struct backend_manager *bm);
void backend_manager_update_health(struct backend_manager *bm, int backend_index, 
                                  int healthy, uint32_t latency_ms);
void backend_manager_increment_connections(struct backend_manager *bm, int backend_index);
void backend_manager_decrement_connections(struct backend_manager *bm, int backend_index);
void backend_manager_record_failure(struct backend_manager *bm, int backend_index);
void backend_manager_get_stats(struct backend_manager *bm, struct lb_config *config_out,
                              uint64_t *total_queries, uint64_t *failed_queries);
void backend_manager_print_status(struct backend_manager *bm);

extern struct backend_manager *g_bm;

#endif // BACKEND_MANAGER_H