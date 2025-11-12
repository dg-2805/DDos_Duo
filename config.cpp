#include "config.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <algorithm>

// Simple JSON-like parser (basic implementation)
// For production, consider using a proper JSON library like jsoncpp or rapidjson

static void trim(std::string& s) {
    s.erase(0, s.find_first_not_of(" \t\n\r"));
    s.erase(s.find_last_not_of(" \t\n\r") + 1);
}

static std::string extract_value(const std::string& line) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return "";
    std::string value = line.substr(colon + 1);
    trim(value);
    // Remove quotes if present
    if (!value.empty() && value[0] == '"') {
        value = value.substr(1);
    }
    if (!value.empty() && value.back() == '"') {
        value.pop_back();
    }
    return value;
}

static int extract_int(const std::string& line, int default_val = 0) {
    std::string val = extract_value(line);
    if (val.empty()) return default_val;
    return std::stoi(val);
}

bool load_config_from_file(const std::string& filename, Config& config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open config file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    std::string current_section;
    Pool* current_pool = nullptr;
    Backend* current_backend = nullptr;
    
    while (std::getline(file, line)) {
        trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == '/') continue;
        
        // Section headers
        if (line == "global:" || line == "[global]") {
            current_section = "global";
            continue;
        }
        if (line.find("pool:") != std::string::npos || line.find("[pool]") != std::string::npos) {
            current_section = "pool";
            config.pools.emplace_back();
            current_pool = &config.pools.back();
            current_pool->name = "pool_" + std::to_string(config.pools.size());
            continue;
        }
        if (line.find("backend:") != std::string::npos || line.find("[backend]") != std::string::npos) {
            current_section = "backend";
            if (current_pool) {
                current_pool->backends.emplace_back();
                current_backend = &current_pool->backends.back();
                current_backend->pool_name = current_pool->name;
            }
            continue;
        }
        
        // Parse key-value pairs
        if (current_section == "global") {
            if (line.find("listen_address:") != std::string::npos) {
                config.listen_address = extract_value(line);
            } else if (line.find("listen_port:") != std::string::npos) {
                config.listen_port = extract_int(line, 53);
            } else if (line.find("xdp_enable:") != std::string::npos) {
                std::string val = extract_value(line);
                config.xdp_enable = (val == "true" || val == "1");
            } else if (line.find("xdp_iface:") != std::string::npos) {
                config.xdp_iface = extract_value(line);
            } else if (line.find("xdp_mode:") != std::string::npos) {
                config.xdp_mode = extract_value(line);
            } else if (line.find("xdp_vip:") != std::string::npos) {
                config.xdp_vip = extract_value(line);
            } else if (line.find("num_workers:") != std::string::npos) {
                config.num_workers = extract_int(line, 0);
            } else if (line.find("health_check_interval_ms:") != std::string::npos) {
                config.health_check_interval_ms = extract_int(line, 2000);
            } else if (line.find("health_check_timeout_ms:") != std::string::npos) {
                config.health_check_timeout_ms = extract_int(line, 1000);
            } else if (line.find("health_check_query_name:") != std::string::npos) {
                config.health_check_query_name = extract_value(line);
            } else if (line.find("enable_rrl:") != std::string::npos) {
                std::string val = extract_value(line);
                config.enable_rrl = (val == "true" || val == "1");
            } else if (line.find("rrl_max_per_second:") != std::string::npos) {
                config.rrl_max_per_second = extract_int(line, 10);
            } else if (line.find("rrl_window_seconds:") != std::string::npos) {
                config.rrl_window_seconds = extract_int(line, 1);
            } else if (line.find("socket_rcvbuf_size:") != std::string::npos) {
                config.socket_rcvbuf_size = extract_int(line, 1024 * 1024);
            } else if (line.find("socket_sndbuf_size:") != std::string::npos) {
                config.socket_sndbuf_size = extract_int(line, 1024 * 1024);
            } else if (line.find("metrics_port:") != std::string::npos) {
                config.metrics_port = extract_int(line, 8080);
            } else if (line.find("enable_metrics:") != std::string::npos) {
                std::string val = extract_value(line);
                config.enable_metrics = (val == "true" || val == "1");
            } else if (line.find("enable_cache:") != std::string::npos) {
                std::string val = extract_value(line);
                config.enable_cache = (val == "true" || val == "1");
            } else if (line.find("cache_ttl_ms:") != std::string::npos) {
                config.cache_ttl_ms = extract_int(line, 2000);
            } else if (line.find("cache_size:") != std::string::npos) {
                config.cache_size = extract_int(line, 65536);
            }
        } else if (current_section == "pool" && current_pool) {
            if (line.find("name:") != std::string::npos) {
                current_pool->name = extract_value(line);
            } else if (line.find("lb_algorithm:") != std::string::npos) {
                current_pool->lb_algorithm = extract_value(line);
            }
        } else if (current_section == "backend" && current_backend) {
            if (line.find("ip:") != std::string::npos) {
                current_backend->ip = extract_value(line);
            } else if (line.find("port:") != std::string::npos) {
                current_backend->port = extract_int(line, 53);
            } else if (line.find("weight:") != std::string::npos) {
                current_backend->weight = extract_int(line, 1);
            }
        }
    }
    
    file.close();
    
    // Auto-detect CPU cores if num_workers is 0
    if (config.num_workers == 0) {
        std::ifstream cpuinfo("/proc/cpuinfo");
        config.num_workers = 0;
        std::string cpu_line;
        while (std::getline(cpuinfo, cpu_line)) {
            if (cpu_line.find("processor") != std::string::npos) {
                config.num_workers++;
            }
        }
        cpuinfo.close();
        if (config.num_workers == 0) {
            config.num_workers = 4;  // Default fallback
        }
    }
    
    return true;
}

bool load_config_from_json(const std::string& json_str, Config& config) {
    // Simplified implementation - for production use a proper JSON parser
    // This is a basic fallback that creates a default config
    std::istringstream iss(json_str);
    return load_config_from_file("", config);  // Not fully implemented
}

void print_config(const Config& config) {
    std::cout << "=== DNS Load Balancer Configuration ===" << std::endl;
    std::cout << "Listen Address: " << config.listen_address << std::endl;
    std::cout << "Listen Port: " << config.listen_port << std::endl;
    std::cout << "Workers: " << config.num_workers << std::endl;
    std::cout << "XDP Enabled: " << (config.xdp_enable ? "yes" : "no") << std::endl;
    if (config.xdp_enable) {
        std::cout << "XDP Iface: " << config.xdp_iface << " Mode: " << config.xdp_mode
                  << " VIP: " << (config.xdp_vip.empty() ? config.listen_address : config.xdp_vip)
                  << std::endl;
    }
    std::cout << "Health Check Interval: " << config.health_check_interval_ms << "ms" << std::endl;
    std::cout << "RRL Enabled: " << (config.enable_rrl ? "yes" : "no") << std::endl;
    std::cout << "RRL Max Per Second: " << config.rrl_max_per_second << std::endl;
    std::cout << "\nPools: " << config.pools.size() << std::endl;
    
    for (const auto& pool : config.pools) {
        std::cout << "  Pool: " << pool.name 
                  << " (LB: " << pool.lb_algorithm << ")" << std::endl;
        for (const auto& backend : pool.backends) {
            std::cout << "    Backend: " << backend.ip << ":" << backend.port 
                      << " (weight: " << backend.weight << ")" << std::endl;
        }
    }
    std::cout << "=======================================" << std::endl;
}

