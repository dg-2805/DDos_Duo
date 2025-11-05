#pragma once

#include "config.hpp"
#include "shared.hpp"
#include <thread>
#include <atomic>
#include <vector>
#include <future>
#include <mutex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// BackendManager handles health checking and maintains backend state
class BackendManager {
public:
    BackendManager(const Config& config, SharedHealthState* shared_state);
    ~BackendManager();
    
    // Start the health check thread
    void start();
    
    // Stop the health check thread
    void stop();
    
    // Run health check loop (called in thread)
    void run();
    
    // Perform health check on a single backend
    bool check_backend_health(const Backend& backend, uint32_t timeout_ms);
    
    // Update shared health state
    void update_shared_state();
    
    // Get healthy backends for a pool
    std::vector<size_t> get_healthy_backend_indices(const std::string& pool_name);
    
private:
    const Config& config_;
    SharedHealthState* shared_state_;
    std::thread health_check_thread_;
    std::atomic<bool> running_;
    
    // Internal backend tracking
    struct BackendState {
        Backend backend;
        bool is_healthy;
        uint64_t last_check_time;
        uint64_t consecutive_failures;
        
        BackendState(const Backend& b) : backend(b), is_healthy(false),
                                        last_check_time(0), consecutive_failures(0) {}
    };
    
    std::vector<BackendState> backend_states_;
    
    // Generate a simple DNS query packet for health checks
    void create_health_check_query(uint8_t* buffer, size_t& len, const std::string& query_name);
    
    // Parse DNS response to verify health
    bool validate_dns_response(const uint8_t* buffer, size_t len);
};

