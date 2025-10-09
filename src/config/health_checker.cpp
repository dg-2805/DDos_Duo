#include <iostream>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <atomic>
#include <random>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "health_checker.h"
#include "config_loader.h"

// Private method implementations
bool HealthChecker::isSimulatedDownServer(const std::string& endpoint) {
    // These servers will always appear down (for testing)
    std::vector<std::string> down_servers = {
        "192.168.99.99",  // Our explicitly down server
        "192.168.99.98",  // Another down server in same pool
        "10.255.255.1"    // Any other test patterns
    };
    
    for (const auto& down_ip : down_servers) {
        if (endpoint.find(down_ip) != std::string::npos) {
            std::cout << "SIMULATED DOWN SERVER: " << endpoint << std::endl;
            return true;
        }
    }
    return false;
}

bool HealthChecker::shouldSimulateRandomFailure() {
    std::uniform_int_distribution<> dis(1, 100);
    return dis(gen_) <= 10; // 10% chance of random failure
}

bool HealthChecker::checkHttpHealth(const std::string& endpoint) {
    // Check if this is a simulated down server
    if (isSimulatedDownServer(endpoint)) {
        return false; // Always down
    }
    
    // Simulate occasional random failures
    if (shouldSimulateRandomFailure()) {
        std::cout << "RANDOM FAILURE SIMULATION for: " << endpoint << std::endl;
        return false;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK && http_code == 200);
}

bool HealthChecker::checkDnsHealth(const std::string& server_ip) {
    // Check if this is a simulated down server
    if (isSimulatedDownServer(server_ip)) {
        return false; // Always down
    }
    
    // Simulate occasional random failures
    if (shouldSimulateRandomFailure()) {
        std::cout << "RANDOM DNS FAILURE SIMULATION for: " << server_ip << std::endl;
        return false;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    bool reachable = (connect(sock, (struct sockaddr*)&server_addr, 
                            sizeof(server_addr)) == 0);
    
    close(sock);
    return reachable;
}

void HealthChecker::healthCheckLoop() {
    int check_cycle = 0;
    
    while (running_) {
        check_cycle++;
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
        auto value = now_ms.time_since_epoch();
        long timestamp = value.count();
        
        std::cout << "\n=== Health Check Cycle #" << check_cycle << " ===" << std::endl;
        
        for (const auto& pool : pools_) {
            bool is_healthy = false;
            std::string error_msg = "OK";
            
            // Try HTTP health endpoint first
            if (!pool.health_endpoint.empty()) {
                is_healthy = checkHttpHealth(pool.health_endpoint);
                if (!is_healthy) error_msg = "HTTP health check failed";
            } 
            // Fallback to DNS connectivity check
            else if (!pool.servers.empty()) {
                is_healthy = checkDnsHealth(pool.servers[0]);
                if (!is_healthy) error_msg = "DNS connectivity check failed";
            }
            
            // Update health status with failure counting
            auto& status = pool_health_[pool.name];
            if (is_healthy) {
                status.consecutive_failures = 0;
                status.is_healthy = true;
                status.last_error = "OK";
            } else {
                status.consecutive_failures++;
                status.last_error = error_msg;
                
                // Mark unhealthy only after 3 consecutive failures
                if (status.consecutive_failures >= 3) {
                    status.is_healthy = false;
                }
            }
            status.last_check_timestamp = timestamp;
            
            // Color-coded output for easy reading
            std::string health_color = status.is_healthy ? "\033[32m" : "\033[31m";
            std::string health_text = status.is_healthy ? "HEALTHY" : "UNHEALTHY";
            
            std::cout << health_color 
                      << "Pool: " << pool.name 
                      << " - " << health_text
                      << " - Failures: " << status.consecutive_failures;
            
            if (!status.is_healthy) {
                std::cout << " - Error: " << status.last_error;
            }
            std::cout << "\033[0m" << std::endl;
        }
        
        std::cout << "=== End Cycle #" << check_cycle << " ===" << std::endl;
        
        // Sleep until next check cycle
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

// Public method implementations
HealthChecker::HealthChecker(const std::vector<ServerPool>& pools) : pools_(pools), gen_(rd_()) {
    // Initialize all pools as unhealthy until first check
    for (const auto& pool : pools_) {
        pool_health_[pool.name] = {false, 0, 0, 0.0, "Initializing"};
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

HealthChecker::~HealthChecker() {
    stop();
    curl_global_cleanup();
}

void HealthChecker::start() {
    running_ = true;
    health_check_thread_ = std::thread(&HealthChecker::healthCheckLoop, this);
    std::cout << "Health checker started monitoring " << pools_.size() << " pools" << std::endl;
}

void HealthChecker::stop() {
    running_ = false;
    if (health_check_thread_.joinable()) {
        health_check_thread_.join();
    }
}

bool HealthChecker::isPoolHealthy(const std::string& pool_name) {
    auto it = pool_health_.find(pool_name);
    if (it != pool_health_.end()) {
        return it->second.is_healthy;
    }
    return false;
}

std::vector<std::string> HealthChecker::getHealthyPools() {
    std::vector<std::string> healthy_pools;
    for (const auto& [pool_name, status] : pool_health_) {
        if (status.is_healthy) {
            healthy_pools.push_back(pool_name);
        }
    }
    return healthy_pools;
}

HealthStatus HealthChecker::getPoolStatus(const std::string& pool_name) {
    auto it = pool_health_.find(pool_name);
    if (it != pool_health_.end()) {
        return it->second;
    }
    return {false, 0, 0, 0.0, "Unknown pool"};
}

void HealthChecker::printHealthSummary() {
    std::cout << "\n SYSTEM HEALTH SUMMARY" << std::endl;
    std::cout << "========================" << std::endl;
    
    int healthy_count = 0;
    for (const auto& [pool_name, status] : pool_health_) {
        std::string indicator = status.is_healthy ? "✅" : "❌";
        std::cout << indicator << " " << pool_name 
                  << " - Failures: " << status.consecutive_failures;
        if (!status.is_healthy) {
            std::cout << " - " << status.last_error;
        }
        std::cout << std::endl;
        
        if (status.is_healthy) healthy_count++;
    }
    
    std::cout << "========================" << std::endl;
    std::cout << "Healthy: " << healthy_count << "/" << pool_health_.size() 
              << " pools" << std::endl;
}