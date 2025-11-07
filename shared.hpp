#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// Maximum number of backends per pool
constexpr size_t MAX_BACKENDS = 1024;
constexpr size_t MAX_POOLS = 64;
constexpr size_t MAX_METRICS_SLOTS = 256;

// Shared memory key (for System V IPC, alternative to mmap file)
constexpr const char* SHM_KEY = "/dns_lb_shared";

// Backend health status
struct BackendHealth {
    char ip[64];           // IPv4 or IPv6 address
    uint16_t port;
    std::atomic<bool> is_healthy;
    std::atomic<uint64_t> requests_sent;
    std::atomic<uint64_t> responses_received;
    std::atomic<uint64_t> errors;
    // EWMA latency in microseconds (smoothed per-backend RTT estimate)
    std::atomic<uint64_t> ewma_latency_us;
    
    // OPTIMIZED: Cached binary IP address to avoid inet_pton on hot path
    uint32_t ip_addr_binary;  // Network byte order
    struct sockaddr_in cached_addr;  // Pre-built sockaddr for fast sending
    
    BackendHealth() : port(53), is_healthy(false), 
                     requests_sent(0), responses_received(0), errors(0),
                     ewma_latency_us(5000), ip_addr_binary(0) {
        ip[0] = '\0';
        memset(&cached_addr, 0, sizeof(cached_addr));
    }
};

// Shared health state for all backends
struct SharedHealthState {
    std::atomic<size_t> backend_count;
    BackendHealth backends[MAX_BACKENDS];
    std::atomic<uint64_t> last_update_time;  // Unix timestamp
    
    SharedHealthState() : backend_count(0), last_update_time(0) {}
};

// Per-worker metrics
struct WorkerMetrics {
    std::atomic<uint64_t> packets_received;
    std::atomic<uint64_t> packets_sent;
    std::atomic<uint64_t> dns_queries;
    std::atomic<uint64_t> dns_responses;
    std::atomic<uint64_t> errors;
    std::atomic<uint64_t> backend_errors;
    std::atomic<uint64_t> rrl_dropped;
    
    WorkerMetrics() : packets_received(0), packets_sent(0), 
                     dns_queries(0), dns_responses(0), 
                     errors(0), backend_errors(0), rrl_dropped(0) {}
};

// Global shared metrics structure
struct SharedMetrics {
    std::atomic<uint64_t> total_qps;
    std::atomic<uint64_t> total_errors;
    std::atomic<uint64_t> total_rrl_dropped;
    WorkerMetrics worker_metrics[MAX_METRICS_SLOTS];  // One per worker
    
    SharedMetrics() : total_qps(0), total_errors(0), total_rrl_dropped(0) {}
};

// Client address structure for tracking in-flight requests
// OPTIMIZED: Use binary IPv4 address (4 bytes) instead of string (64 bytes)
struct ClientAddress {
    uint32_t ip_addr;        // Binary IPv4 address (network byte order)
    uint16_t port;
    uint16_t original_tx_id;
    uint64_t timestamp_ms;  // Request timestamp for timeout handling
    
    ClientAddress() : ip_addr(0), port(0), original_tx_id(0), timestamp_ms(0) {}
    
    ClientAddress(uint32_t ip, uint16_t p, uint16_t tx_id, uint64_t ts = 0) 
        : ip_addr(ip), port(p), original_tx_id(tx_id), timestamp_ms(ts) {}
    
    // Helper to convert sockaddr_in to binary IP
    static uint32_t from_sockaddr(const struct sockaddr_in* addr) {
        return addr ? addr->sin_addr.s_addr : 0;
    }
    
    // Helper to convert back to sockaddr_in for sending
    void to_sockaddr(struct sockaddr_in* addr) const {
        if (addr) {
            memset(addr, 0, sizeof(*addr));
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = ip_addr;
            addr->sin_port = htons(port);
        }
    }
};

// RRL (Response Rate Limiting) tracking structure
struct RRLBucket {
    uint64_t queries;
    uint64_t window_start;  // Time window start in nanoseconds
    bool valid;
    
    RRLBucket() : queries(0), window_start(0), valid(false) {}
};

