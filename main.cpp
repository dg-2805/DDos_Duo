#include "config.hpp"
#include "shared.hpp"
#include "backend_manager.hpp"
#include "worker.hpp"
#include <iostream>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <atomic>

static std::vector<std::thread> worker_threads;
static BackendManager* backend_manager = nullptr;
static SharedHealthState* shared_health = nullptr;
static SharedMetrics* shared_metrics = nullptr;
static std::atomic<bool> running(true);

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        std::cout << "\nReceived signal, shutting down gracefully..." << std::endl;
        running.store(false);
        
        // Stop backend manager
        if (backend_manager) {
            backend_manager->stop();
        }
        
        // Wait for all worker threads
        for (auto& t : worker_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        
        exit(0);
    }
}

// Prometheus metrics server (runs in separate thread)
void metrics_server_thread(uint16_t port, SharedMetrics* metrics, SharedHealthState* health) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("metrics socket");
        return;
    }
    
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind metrics");
        close(sock);
        return;
    }
    
    if (listen(sock, 5) < 0) {
        perror("listen metrics");
        close(sock);
        return;
    }
    
    std::cout << "Metrics server listening on port " << port << std::endl;
    
    while (running.load()) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (errno != EINTR) {
                perror("accept");
            }
            continue;
        }
        
        // Read HTTP request (simple - just check for /metrics path)
        char request[1024] = {0};
        ssize_t bytes_read = recv(client_fd, request, sizeof(request) - 1, 0);
        
        // Always respond with metrics (ignore path for simplicity)
        
        // Prometheus-formatted metrics response
        std::ostringstream response;
        response << "HTTP/1.1 200 OK\r\n";
        response << "Content-Type: text/plain; version=0.0.4\r\n";
        response << "Connection: close\r\n\r\n";
        
        // Prometheus format: HELP and TYPE comments
        response << "# HELP dns_loadbalancer_total_queries Total DNS queries processed\n";
        response << "# TYPE dns_loadbalancer_total_queries counter\n";
        response << "dns_loadbalancer_total_queries " << metrics->total_qps.load() << "\n\n";
        
        response << "# HELP dns_loadbalancer_total_errors Total DNS errors\n";
        response << "# TYPE dns_loadbalancer_total_errors counter\n";
        response << "dns_loadbalancer_total_errors " << metrics->total_errors.load() << "\n\n";
        
        response << "# HELP dns_loadbalancer_total_rrl_dropped Total packets dropped by RRL\n";
        response << "# TYPE dns_loadbalancer_total_rrl_dropped counter\n";
        response << "dns_loadbalancer_total_rrl_dropped " << metrics->total_rrl_dropped.load() << "\n\n";
        
        // Per-worker metrics with labels
        response << "# HELP dns_loadbalancer_worker_packets_received Packets received per worker\n";
        response << "# TYPE dns_loadbalancer_worker_packets_received counter\n";
        for (size_t i = 0; i < MAX_METRICS_SLOTS; i++) {
            const auto& wm = metrics->worker_metrics[i];
            uint64_t received = wm.packets_received.load();
            if (received > 0 || wm.errors.load() > 0 || wm.packets_sent.load() > 0) {
                response << "dns_loadbalancer_worker_packets_received{worker=\"" << i << "\"} " 
                         << received << "\n";
            }
        }
        response << "\n";
        
        response << "# HELP dns_loadbalancer_worker_packets_sent Packets sent per worker\n";
        response << "# TYPE dns_loadbalancer_worker_packets_sent counter\n";
        for (size_t i = 0; i < MAX_METRICS_SLOTS; i++) {
            const auto& wm = metrics->worker_metrics[i];
            uint64_t sent = wm.packets_sent.load();
            if (sent > 0 || wm.packets_received.load() > 0) {
                response << "dns_loadbalancer_worker_packets_sent{worker=\"" << i << "\"} " 
                         << sent << "\n";
            }
        }
        response << "\n";
        
        response << "# HELP dns_loadbalancer_worker_errors Errors per worker\n";
        response << "# TYPE dns_loadbalancer_worker_errors counter\n";
        for (size_t i = 0; i < MAX_METRICS_SLOTS; i++) {
            const auto& wm = metrics->worker_metrics[i];
            uint64_t errors = wm.errors.load();
            if (errors > 0 || wm.packets_received.load() > 0) {
                response << "dns_loadbalancer_worker_errors{worker=\"" << i << "\"} " 
                         << errors << "\n";
            }
        }
        response << "\n";
        
        response << "# HELP dns_loadbalancer_worker_rrl_dropped RRL dropped packets per worker\n";
        response << "# TYPE dns_loadbalancer_worker_rrl_dropped counter\n";
        for (size_t i = 0; i < MAX_METRICS_SLOTS; i++) {
            const auto& wm = metrics->worker_metrics[i];
            uint64_t dropped = wm.rrl_dropped.load();
            if (dropped > 0) {
                response << "dns_loadbalancer_worker_rrl_dropped{worker=\"" << i << "\"} " 
                         << dropped << "\n";
            }
        }
        response << "\n";
        
        // Backend health metrics
        if (health) {
            size_t backend_count = health->backend_count.load();
            response << "# HELP dns_loadbalancer_backend_count Number of configured backends\n";
            response << "# TYPE dns_loadbalancer_backend_count gauge\n";
            response << "dns_loadbalancer_backend_count " << backend_count << "\n\n";
            
            response << "# HELP dns_loadbalancer_backend_healthy Backend health status (1=healthy, 0=unhealthy)\n";
            response << "# TYPE dns_loadbalancer_backend_healthy gauge\n";
            for (size_t i = 0; i < backend_count && i < MAX_BACKENDS; i++) {
                const auto& backend = health->backends[i];
                bool healthy = backend.is_healthy.load();
                response << "dns_loadbalancer_backend_healthy{backend=\"" << i 
                         << "\",ip=\"" << backend.ip << "\",port=\"" << backend.port << "\"} " 
                         << (healthy ? 1 : 0) << "\n";
            }
            response << "\n";
            
            response << "# HELP dns_loadbalancer_backend_requests_sent Requests sent to backend\n";
            response << "# TYPE dns_loadbalancer_backend_requests_sent counter\n";
            for (size_t i = 0; i < backend_count && i < MAX_BACKENDS; i++) {
                const auto& backend = health->backends[i];
                uint64_t requests = backend.requests_sent.load();
                response << "dns_loadbalancer_backend_requests_sent{backend=\"" << i 
                         << "\",ip=\"" << backend.ip << "\"} " << requests << "\n";
            }
            response << "\n";
            
            response << "# HELP dns_loadbalancer_backend_responses_received Responses received from backend\n";
            response << "# TYPE dns_loadbalancer_backend_responses_received counter\n";
            for (size_t i = 0; i < backend_count && i < MAX_BACKENDS; i++) {
                const auto& backend = health->backends[i];
                uint64_t responses = backend.responses_received.load();
                response << "dns_loadbalancer_backend_responses_received{backend=\"" << i 
                         << "\",ip=\"" << backend.ip << "\"} " << responses << "\n";
            }
            response << "\n";
            
            response << "# HELP dns_loadbalancer_backend_errors Backend errors\n";
            response << "# TYPE dns_loadbalancer_backend_errors counter\n";
            for (size_t i = 0; i < backend_count && i < MAX_BACKENDS; i++) {
                const auto& backend = health->backends[i];
                uint64_t errors = backend.errors.load();
                response << "dns_loadbalancer_backend_errors{backend=\"" << i 
                         << "\",ip=\"" << backend.ip << "\"} " << errors << "\n";
            }
            response << "\n";
            
            response << "# HELP dns_loadbalancer_backend_latency_us Backend EWMA latency in microseconds\n";
            response << "# TYPE dns_loadbalancer_backend_latency_us gauge\n";
            for (size_t i = 0; i < backend_count && i < MAX_BACKENDS; i++) {
                const auto& backend = health->backends[i];
                uint64_t latency = backend.ewma_latency_us.load();
                response << "dns_loadbalancer_backend_latency_us{backend=\"" << i 
                         << "\",ip=\"" << backend.ip << "\"} " << latency << "\n";
            }
        }
        
        std::string response_str = response.str();
        send(client_fd, response_str.c_str(), response_str.length(), 0);
        close(client_fd);
    }
    
    close(sock);
}

int main(int argc, char* argv[]) {
    std::cout << "DNS Load Balancer v1.0" << std::endl;
    
    // Parse command line arguments
    std::string config_file = "config.txt";
    std::string simulate_latency = "";
    std::string cli_latencies = "";
    std::string cli_weights = "";
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--simulate-latency" && i + 1 < argc) {
            simulate_latency = argv[++i];
        } else if ((arg == "--latency" || arg == "--latencies") && i + 1 < argc) {
            cli_latencies = argv[++i];
        } else if (arg == "--weights" && i + 1 < argc) {
            cli_weights = argv[++i];
        } else if (arg.find("--") != 0 && config_file == "config.txt") {
            // First non-option argument is config file
            config_file = arg;
        }
    }
    
    // Load configuration
    Config config;
    if (!load_config_from_file(config_file, config)) {
        std::cerr << "Failed to load configuration. Using defaults." << std::endl;
        // Create a default config with a sample backend
        config.pools.emplace_back();
        config.pools[0].name = "default";
        config.pools[0].backends.emplace_back();
        config.pools[0].backends[0].ip = "8.8.8.8";
        config.pools[0].backends[0].port = 53;
        config.pools[0].backends[0].weight = 1;
    }
    
    // Apply latency simulation if provided
    if (!cli_latencies.empty()) {
        config.simulate_latency_us = cli_latencies;
        std::cout << "Latency simulation (CLI) enabled: " << cli_latencies << " microseconds" << std::endl;
    } else if (!simulate_latency.empty()) {
        config.simulate_latency_us = simulate_latency; // backward-compat flag
        std::cout << "Latency simulation enabled: " << simulate_latency << " microseconds" << std::endl;
    }
    
    // Apply backend weights from CLI if provided (assign sequentially across all backends)
    if (!cli_weights.empty()) {
        std::istringstream iss(cli_weights);
        std::string token;
        std::vector<int> weights;
        while (std::getline(iss, token, ',')) {
            try {
                int w = std::stoi(token);
                if (w <= 0) w = 1;
                weights.push_back(w);
            } catch (...) {
                // ignore invalid
            }
        }
        if (!weights.empty()) {
            size_t idx = 0;
            for (auto& pool : config.pools) {
                for (auto& be : pool.backends) {
                    if (idx < weights.size()) {
                        be.weight = weights[idx++];
                    } else {
                        break;
                    }
                }
                if (idx >= weights.size()) break;
            }
            std::cout << "Applied CLI backend weights for " << std::min(weights.size(), (size_t)3) << " backends" << std::endl;
        }
    }
    
    print_config(config);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGCHLD, SIG_IGN);  // Ignore child exits (we'll check with waitpid)
    
    // Create shared memory for health state
    size_t shared_size = sizeof(SharedHealthState);
    shared_health = (SharedHealthState*)mmap(nullptr, shared_size,
                                             PROT_READ | PROT_WRITE,
                                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared_health == MAP_FAILED) {
        perror("mmap shared_health");
        return 1;
    }
    new(shared_health) SharedHealthState();
    
    // Create shared memory for metrics
    size_t metrics_size = sizeof(SharedMetrics);
    shared_metrics = (SharedMetrics*)mmap(nullptr, metrics_size,
                                          PROT_READ | PROT_WRITE,
                                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared_metrics == MAP_FAILED) {
        perror("mmap shared_metrics");
        return 1;
    }
    new(shared_metrics) SharedMetrics();
    
    // Start backend manager
    backend_manager = new BackendManager(config, shared_health);
    backend_manager->start();
    
    std::cout << "Backend manager started" << std::endl;
    
    // Start Prometheus metrics server thread
    std::thread metrics_thread;
    if (config.enable_metrics) {
        metrics_thread = std::thread(metrics_server_thread, config.metrics_port, shared_metrics, shared_health);
        metrics_thread.detach();
        std::cout << "Prometheus metrics endpoint: http://localhost:" << config.metrics_port << "/metrics" << std::endl;
    }
    
    // OPTIMIZED: Start worker threads instead of processes
    // Threads have much lower overhead than processes (no IPC, shared memory, fork overhead)
    std::cout << "Starting " << config.num_workers << " worker threads..." << std::endl;
    
    for (int i = 0; i < config.num_workers; i++) {
        worker_threads.emplace_back([i, &config, shared_health, shared_metrics]() {
            Worker worker(config, i, shared_health, shared_metrics);
            worker.run();
        });
        std::cout << "Started worker thread " << i << std::endl;
    }
    
    std::cout << "All workers started. Load balancer is running." << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;
    
    // Main supervisor loop - wait for signal
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Cleanup
    if (backend_manager) {
        backend_manager->stop();
        delete backend_manager;
    }
    
    // Unmap shared memory
    if (shared_health) {
        munmap(shared_health, sizeof(SharedHealthState));
    }
    if (shared_metrics) {
        munmap(shared_metrics, sizeof(SharedMetrics));
    }
    
    return 0;
}

