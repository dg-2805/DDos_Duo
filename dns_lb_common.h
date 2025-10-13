#ifndef DNS_LB_COMMON_H
#define DNS_LB_COMMON_H

#include <stdint.h>
#include <netinet/in.h>

#define DNS_PORT 53
#define MAX_BACKENDS 16
#define MAX_DNS_NAME_LENGTH 256

// DNS protocol constants
#define DNS_QR_RESPONSE 0x8000
#define DNS_OPCODE_QUERY 0x0000
#define DNS_RCODE_NOERROR 0x0000
#define DNS_RA_RECURSION_AVAILABLE 0x0080

// DNS record types
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28

// Load balancing algorithms
typedef enum {
    LB_ROUND_ROBIN = 0,
    LB_WEIGHTED_ROUND_ROBIN = 1,
    LB_LEAST_CONNECTIONS = 2,
    LB_LATENCY_BASED = 3,
    LB_GEO_AWARE = 4
} lb_algorithm_t;

// Backend server definition
struct backend_server {
    uint32_t ip_addr;
    uint16_t port;
    uint8_t weight;
    uint8_t healthy;
    uint32_t current_connections;
    uint32_t max_connections;
    uint32_t latency_ms;
    uint64_t total_queries;
    uint64_t failed_queries;
    char region[32];
};

// Load balancer configuration
struct lb_config {
    lb_algorithm_t algorithm;
    uint32_t backend_count;
    struct backend_server backends[MAX_BACKENDS];
    uint32_t health_check_interval;
    uint32_t max_retries;
    uint32_t timeout_ms;
};

// DNS session tracking
struct dns_session {
    uint32_t client_ip;
    uint16_t client_port;
    uint16_t query_id;
    uint32_t backend_index;
    uint64_t timestamp;
};

#endif // DNS_LB_COMMON_H