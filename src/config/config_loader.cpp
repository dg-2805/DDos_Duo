#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "config_loader.h"

using json = nlohmann::json;

std::vector<ServerPool> ConfigLoader::loadBackends(const std::string& config_path) {
    std::vector<ServerPool> pools;
    
    try {
        std::ifstream config_file(config_path);
        if (!config_file.is_open()) {
            std::cerr << "❌ Cannot open config file: " << config_path << " (file not found or permission denied)" << std::endl;
            return pools;
        }
        
        json config = json::parse(config_file);
        
        for (const auto& pool_config : config["pools"]) {
            ServerPool pool;
            pool.name = pool_config["name"];
            pool.health_endpoint = pool_config["health_endpoint"];
            pool.geo_region = pool_config["geo_region"];
            pool.check_interval_sec = pool_config["check_interval_sec"];
            
            // Load servers
            for (const auto& server_config : pool_config["servers"]) {
                std::string server_ip = server_config["ip"];
                pool.servers.push_back(server_ip);
            }
            
            pools.push_back(pool);
        }
        
        std::cout << "Loaded " << pools.size() << " server pools from " 
                  << config_path << std::endl;
                  
    } catch (const std::exception& e) {
        std::cerr << "Error loading config from " << config_path << ": " << e.what() << std::endl;
    }
    
    return pools;
}