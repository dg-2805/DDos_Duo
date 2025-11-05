#pragma once

#include "config.hpp"
#include "shared.hpp"
#include "dns.hpp"
#include <atomic>
#include <cstdint>
#include <string>
#include <sys/socket.h>
#include <cstring>

// Worker process - handles high-performance DNS load balancing
class Worker {
public:
    Worker(const Config& config, int worker_id, SharedHealthState* shared_health,
           SharedMetrics* shared_metrics);
    ~Worker();
    
    // Main worker loop
    int run();
    
private:
    const Config& config_;
    int worker_id_;
    SharedHealthState* shared_health_;
    SharedMetrics* shared_metrics_;
    
    int udp_socket_;
    int epoll_fd_;
    int backend_socket_;
    
    // OPTIMIZED: Use array-based storage for pending requests (faster than hash map)
    // Direct indexing by transaction ID modulo, with linear probing for collisions
    static constexpr size_t PENDING_REQUESTS_SIZE = 65536;  // 2^16 for 16-bit TX IDs
    struct PendingRequestSlot {
        uint16_t tx_id;           // Stored TX ID (0 = empty)
        ClientAddress client;
        bool valid;
        
        PendingRequestSlot() : tx_id(0), valid(false) {}
    };
    PendingRequestSlot* pending_requests_;  // Heap-allocated array
    std::atomic<uint16_t> next_backend_tx_id_;
    size_t cleanup_index_;  // For incremental cleanup
    
    // OPTIMIZED: Direct backend arrays instead of complex lookups
    struct BackendCache {
        size_t healthy_indices[64];
        size_t healthy_count;
        size_t rr_counter;
        uint64_t last_update_ns;
    };
    BackendCache backend_cache_;
    
    // Round-robin counter (per pool, but we only use first pool)
    size_t pool_rr_counter_;
    
    // OPTIMIZED: RRL with integer-based hashing (no strings)
    struct RRLState {
        struct Bucket {
            uint64_t queries;
            uint64_t window_start;
            bool valid;
        };
        Bucket buckets_[4096];  // Fixed-size hash table
        uint64_t window_nanos_;
        
        uint32_t hash_ip(uint32_t ip) const {
            // Simple hash function for IPv4
            return ip % 4096;
        }
    } rrl_state_;
    
    // OPTIMIZED: Batched metrics to reduce atomic contention
    struct MetricsBatch {
        uint64_t packets_received;
        uint64_t packets_sent;
        uint64_t errors;
        uint64_t rrl_dropped;
        uint64_t last_flush_ns;
    } metrics_batch_;
    
    // OPTIMIZED: Batching structures for recvmmsg/sendmmsg
    static constexpr int BATCH_SIZE = 256;  // Batch up to 256 packets per syscall
    struct PacketBuffer {
        alignas(64) uint8_t data[DNS_EDNS_MAX_PACKET_SIZE];
        struct sockaddr_storage addr;
        socklen_t addr_len;
        ssize_t len;
    };
    PacketBuffer client_batch_[BATCH_SIZE];
    PacketBuffer response_batch_[BATCH_SIZE];
    int pending_responses_;  // Number of responses waiting to be sent
    
    // Per-worker packet cache (wire-format packet cache)
    struct CacheEntry {
        uint64_t key;            // hash of question section
        uint64_t expiry_ms;      // absolute expiry time in ms
        uint16_t len;            // response length
        bool valid;
        alignas(64) uint8_t data[DNS_EDNS_MAX_PACKET_SIZE];
        CacheEntry() : key(0), expiry_ms(0), len(0), valid(false) {}
    };
    CacheEntry* cache_;
    size_t cache_capacity_;
    
    // Initialize worker
    bool initialize();
    
    // Set CPU affinity
    bool set_cpu_affinity(int cpu_core);
    
    // Setup network socket
    bool setup_socket();
    
    // Setup epoll
    bool setup_epoll();
    
    // Main event loop
    void event_loop();
    
    // Handle incoming packet from client (mutates buffer in-place)
    void handle_client_packet(uint8_t* buffer, size_t len,
                              const struct sockaddr* client_addr, socklen_t client_len);
    
    // Handle response from backend
    void handle_backend_response(const uint8_t* buffer, size_t len);
    
    // Forward query to backend (optimized with binary IP)
    bool forward_to_backend(uint8_t* buffer, size_t len, uint16_t original_tx_id,
                           uint32_t client_ip, uint16_t client_port);
    
    // Select backend using direct array lookup (optimized)
    size_t select_backend_direct(uint32_t client_ip);
    
    // RRL check with binary IP - returns true if request should be dropped
    bool check_rrl_binary(uint32_t client_ip);
    
    // Update RRL bucket with binary IP
    void update_rrl_bucket_binary(uint32_t client_ip);
    
    // Incremental cleanup (only clean portion of array)
    void cleanup_expired_requests_incremental();
    
    // Flush batched metrics
    void flush_metrics();
    
    // OPTIMIZED: Batch receive/send operations using recvmmsg/sendmmsg
    void drain_client_packets_batch();
    void drain_backend_responses_batch();
    void flush_batched_responses();
    void queue_response_for_batch(const uint8_t* buffer, size_t len, 
                                   const struct sockaddr_in* client_addr);
    
    // Cache helpers
    inline uint64_t fnv1a_64(const uint8_t* data, size_t len) const {
        uint64_t hash = 1469598103934665603ULL;
        for (size_t i = 0; i < len; ++i) {
            hash ^= (uint64_t)data[i];
            hash *= 1099511628211ULL;
        }
        return hash;
    }
    bool extract_question_section(const uint8_t* buffer, size_t len,
                                  size_t& q_start, size_t& q_len) const;
    bool cache_lookup_and_respond(uint8_t* query_buf, size_t len, uint16_t client_txid,
                                  const struct sockaddr_in* client_addr);
    void cache_insert_from_response(const uint8_t* resp_buf, size_t len);
};

