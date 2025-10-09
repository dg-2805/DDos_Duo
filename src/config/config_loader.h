#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

#include <string>
#include <vector>

#ifndef CONFIG_LOADER_SERVER_POOL
#define CONFIG_LOADER_SERVER_POOL

struct ServerPool {
    std::string name;
    std::vector<std::string> servers;
    std::string health_endpoint;
    std::string geo_region;
    int check_interval_sec;
};

#endif // CONFIG_LOADER_SERVER_POOL

class ConfigLoader {
public:
    static std::vector<ServerPool> loadBackends(const std::string& config_path);
};

#endif // CONFIG_LOADER_H