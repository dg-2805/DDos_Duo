#ifndef HEALTH_CHECKER_H
#define HEALTH_CHECKER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <thread>
#include <random>
#include "config_loader.h"

#ifndef HEALTH_CHECKER_STATUS
#define HEALTH_CHECKER_STATUS

struct HealthStatus {
    bool is_healthy;
    int consecutive_failures;
    long last_check_timestamp;
    double response_time_ms;
    std::string last_error;
};

#endif // HEALTH_CHECKER_STATUS

class HealthChecker {
private:
    std::unordered_map<std::string, HealthStatus> pool_health_;
    std::vector<ServerPool> pools_;
    std::atomic<bool> running_{false};
    std::thread health_check_thread_;
    std::random_device rd_;
    std::mt19937 gen_;
    
    bool isSimulatedDownServer(const std::string& endpoint);
    bool shouldSimulateRandomFailure();
    bool checkHttpHealth(const std::string& endpoint);
    bool checkDnsHealth(const std::string& server_ip);
    void healthCheckLoop();

public:
    HealthChecker(const std::vector<ServerPool>& pools);
    ~HealthChecker();
    
    void start();
    void stop();
    bool isPoolHealthy(const std::string& pool_name);
    std::vector<std::string> getHealthyPools();
    HealthStatus getPoolStatus(const std::string& pool_name);
    void printHealthSummary();
};

#endif // HEALTH_CHECKER_H