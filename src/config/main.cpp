#include "health_checker.h"
#include "config_loader.h"

int main() {
    // Load configuration
    auto pools = ConfigLoader::loadBackends("config/backends.json");
    
    // Start health checker
    HealthChecker health_checker(pools);
    health_checker.start();
    
    // Main server loop...
    // Load balancer can now instantly check health:
    // if (health_checker.isPoolHealthy("us-east")) { ... }
    
    // Keep running...
    std::this_thread::sleep_for(std::chrono::seconds(60));
    
    health_checker.stop();
    return 0;#include <iostream>
#include <thread>
#include <chrono>
#include "config_loader.cpp"  // Or create proper headers
#include "health_checker.cpp"

int main() {
    std::cout << "🚀 STARTING HEALTH CHECK DEMO" << std::endl;
    
    // Try multiple config paths
    std::vector<std::string> possible_paths = {
        "backends.json",                    // Build directory
        "../src/config/backends.json",      // Source directory  
        "src/config/backends.json"          // Relative to executable
    };
    
    std::vector<ServerPool> pools;
    for (const auto& path : possible_paths) {
        pools = ConfigLoader::loadBackends(path);
        if (!pools.empty()) {
            std::cout << "✓ Loaded config from: " << path << std::endl;
            break;
        }
    }
    
    if (pools.empty()) {
        std::cerr << "❌ Could not load config from any location" << std::endl;
        return 1;
    }
    
    // Rest of your demo code...
    HealthChecker health_checker(pools);
    health_checker.start();
    
    std::this_thread::sleep_for(std::chrono::seconds(35));
    health_checker.printHealthSummary();
    health_checker.stop();
    
    return 0;
}
}