#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Backend server definition
struct Backend {
    std::string ip;
    uint16_t port;
    int weight;  // For weighted round-robin
    std::string pool_name;
    
    Backend() : port(53), weight(1) {}
};

// Load balancing pool
struct Pool {
    std::string name;
    std::vector<Backend> backends;
    std::string lb_algorithm;  // "round_robin", "weighted_round_robin", "geoproximity"
    
    Pool() : lb_algorithm("round_robin") {}
};

// Main configuration structure
struct Config {
    std::string listen_address;
    uint16_t listen_port;
    int num_workers;  // Number of worker processes (0 = auto-detect from CPU cores)
    std::vector<Pool> pools;
    
    // Health check settings
    uint32_t health_check_interval_ms;
    uint32_t health_check_timeout_ms;
    std::string health_check_query_name;  // DNS name to query for health checks
    
    // RRL (Response Rate Limiting) settings
    bool enable_rrl;
    uint32_t rrl_max_per_second;
    uint32_t rrl_window_seconds;
    
    // Socket buffer sizes
    uint32_t socket_rcvbuf_size;
    uint32_t socket_sndbuf_size;
    
    // Metrics settings
    uint16_t metrics_port;  // HTTP port for metrics endpoint
    bool enable_metrics;

    // Packet cache
    bool enable_cache;
    uint32_t cache_ttl_ms;     // TTL for cached responses
    uint32_t cache_size;       // Number of cache entries (power of two recommended)
    
    Config() : listen_address("0.0.0.0"), listen_port(53),
               num_workers(0), health_check_interval_ms(2000),
               health_check_timeout_ms(1000), health_check_query_name("health.check."),
               enable_rrl(true), rrl_max_per_second(10),
               rrl_window_seconds(1), socket_rcvbuf_size(1024 * 1024),
               socket_sndbuf_size(1024 * 1024), metrics_port(8080),
               enable_metrics(true),
               enable_cache(true), cache_ttl_ms(2000), cache_size(65536) {}
};

// Configuration loading functions
bool load_config_from_file(const std::string& filename, Config& config);
bool load_config_from_json(const std::string& json_str, Config& config);
void print_config(const Config& config);

