#include "backend_manager.hpp"
#include "dns.hpp"
#include <cstring>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <chrono>
#include <algorithm>
#include <thread>
#include <future>
#include <cerrno>

BackendManager::BackendManager(const Config& config, SharedHealthState* shared_state)
    : config_(config), shared_state_(shared_state), running_(false) {
    
    // Build backend_states_ from all pools
    for (const auto& pool : config_.pools) {
        for (const auto& backend : pool.backends) {
            backend_states_.emplace_back(backend);
        }
    }
}

BackendManager::~BackendManager() {
    stop();
}

void BackendManager::start() {
    if (running_) return;
    running_ = true;
    health_check_thread_ = std::thread(&BackendManager::run, this);
}

void BackendManager::stop() {
    if (!running_) return;
    running_ = false;
    if (health_check_thread_.joinable()) {
        health_check_thread_.join();
    }
}

void BackendManager::run() {
    auto last_update = std::chrono::steady_clock::now();
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_update).count();
        
        if (elapsed >= config_.health_check_interval_ms) {
            // OPTIMIZED: Parallel health checks using async (non-blocking)
            // Launch all health checks concurrently to minimize total time
            std::vector<std::future<bool>> futures;
            
            for (auto& backend_state : backend_states_) {
                // Use full timeout per backend when parallel (not divided)
                futures.push_back(std::async(std::launch::async, [this, &backend_state]() {
                    return check_backend_health(backend_state.backend, config_.health_check_timeout_ms);
                }));
            }
            
            // Wait for all health checks and update states
            for (size_t i = 0; i < backend_states_.size() && i < futures.size(); i++) {
                bool healthy = futures[i].get();
                
                auto& backend_state = backend_states_[i];
                if (healthy) {
                    backend_state.consecutive_failures = 0;
                    backend_state.is_healthy = true;
                } else {
                    backend_state.consecutive_failures++;
                    if (backend_state.consecutive_failures >= 2) {
                        backend_state.is_healthy = false;
                    }
                }
                
                backend_state.last_check_time = 
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
            }
            
            // Update shared memory
            update_shared_state();
            
            last_update = now;
        }
        
        // OPTIMIZED: Reduced sleep interval for faster health check updates
        std::this_thread::sleep_for(std::chrono::milliseconds(50));  // Was 100ms
    }
}

bool BackendManager::check_backend_health(const Backend& backend, uint32_t timeout_ms) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    
    // OPTIMIZED: Use non-blocking I/O with select for timeout (faster than blocking)
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Create server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(backend.port);
    
    if (inet_pton(AF_INET, backend.ip.c_str(), &server_addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }
    
    // Create health check query
    uint8_t query_buffer[DNS_MAX_PACKET_SIZE];
    size_t query_len = 0;
    create_health_check_query(query_buffer, query_len, config_.health_check_query_name);
    
    // Send query with non-blocking flag
    ssize_t sent = sendto(sock, query_buffer, query_len, MSG_DONTWAIT,
                         (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            close(sock);
            return false;
        }
        // If EAGAIN, socket buffer might be full, but try to receive anyway
    }
    
    // OPTIMIZED: Use select with timeout for non-blocking receive (faster)
    uint8_t response_buffer[DNS_MAX_PACKET_SIZE];
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    // Wait for response with timeout (non-blocking)
    int select_result = select(sock + 1, &read_fds, nullptr, nullptr, &tv);
    if (select_result <= 0 || !FD_ISSET(sock, &read_fds)) {
        close(sock);
        return false;  // Timeout or error
    }
    
    // Receive response (non-blocking, should have data available)
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t received = recvfrom(sock, response_buffer, sizeof(response_buffer), MSG_DONTWAIT,
                               (struct sockaddr*)&from_addr, &from_len);
    close(sock);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;  // No data available (shouldn't happen after select)
        }
        return false;
    }
    
    return validate_dns_response(response_buffer, received);
}

void BackendManager::update_shared_state() {
    if (!shared_state_) return;
    
    size_t count = 0;
    for (const auto& backend_state : backend_states_) {
        if (count >= MAX_BACKENDS) break;
        
        auto& shared_backend = shared_state_->backends[count];
        strncpy(shared_backend.ip, backend_state.backend.ip.c_str(), sizeof(shared_backend.ip) - 1);
        shared_backend.ip[sizeof(shared_backend.ip) - 1] = '\0';
        shared_backend.port = backend_state.backend.port;
        
        // OPTIMIZED: Cache binary IP and sockaddr to avoid inet_pton on hot path
        if (inet_pton(AF_INET, backend_state.backend.ip.c_str(), &shared_backend.cached_addr.sin_addr) > 0) {
            shared_backend.ip_addr_binary = shared_backend.cached_addr.sin_addr.s_addr;
            shared_backend.cached_addr.sin_family = AF_INET;
            shared_backend.cached_addr.sin_port = htons(backend_state.backend.port);
        } else {
            shared_backend.ip_addr_binary = 0;
            memset(&shared_backend.cached_addr, 0, sizeof(shared_backend.cached_addr));
        }
        
        // Use release semantics to ensure health state is visible to workers
        shared_backend.is_healthy.store(backend_state.is_healthy, std::memory_order_release);
        
        count++;
    }
    
    // Use release semantics to ensure all backend data is visible before count update
    shared_state_->backend_count.store(count, std::memory_order_release);
    shared_state_->last_update_time.store(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::vector<size_t> BackendManager::get_healthy_backend_indices(const std::string& pool_name) {
    std::vector<size_t> indices;
    
    for (size_t i = 0; i < backend_states_.size(); i++) {
        if (backend_states_[i].backend.pool_name == pool_name &&
            backend_states_[i].is_healthy) {
            indices.push_back(i);
        }
    }
    
    return indices;
}

void BackendManager::create_health_check_query(uint8_t* buffer, size_t& len, const std::string& query_name) {
    if (!buffer) {
        len = 0;
        return;
    }
    
    // Create a simple A record query
    DNSHeader header;
    header.id = htons(0x1234);
    header.flags = htons(0x0100);  // Standard query
    header.qdcount = htons(1);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    
    memcpy(buffer, &header, sizeof(header));
    size_t offset = sizeof(header);
    
    // Encode domain name
    std::string name = query_name;
    size_t dot_pos = 0;
    while (dot_pos < name.length()) {
        size_t next_dot = name.find('.', dot_pos);
        if (next_dot == std::string::npos) next_dot = name.length();
        
        size_t label_len = next_dot - dot_pos;
        if (label_len > 63) label_len = 63;
        
        buffer[offset++] = static_cast<uint8_t>(label_len);
        for (size_t i = 0; i < label_len && offset < DNS_MAX_PACKET_SIZE; i++) {
            buffer[offset++] = name[dot_pos + i];
        }
        
        dot_pos = next_dot + 1;
    }
    buffer[offset++] = 0;  // Null terminator
    
    // QTYPE: A record (1)
    uint16_t qtype = htons(1);
    memcpy(buffer + offset, &qtype, sizeof(uint16_t));
    offset += 2;
    
    // QCLASS: IN (1)
    uint16_t qclass = htons(1);
    memcpy(buffer + offset, &qclass, sizeof(uint16_t));
    offset += 2;
    
    len = offset;
}

bool BackendManager::validate_dns_response(const uint8_t* buffer, size_t len) {
    if (!buffer || len < sizeof(DNSHeader)) return false;
    
    DNSHeader header;
    if (!DNS::parse_header(buffer, len, header)) return false;
    
    // Check if it's a response (QR bit = 1)
    if (!DNS::is_response(buffer)) return false;
    
    // Check for errors (basic validation)
    // Accept any response code (even errors indicate the server is alive)
    (void)DNS::get_rcode(buffer);  // Suppress unused warning
    
    return true;
}

