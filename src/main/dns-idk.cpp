#include <boost/asio.hpp>
#include <ldns/ldns.h>
#include <iostream>
#include <thread>
#include <vector>
#include <signal.h>
#include <unistd.h>
#include "../config/config_loader.h"
#include "../config/health_checker.h"
using namespace std;

using boost::asio::ip::udp;

const int DNS_PORT = 5353; // 53 if root
const char* ZONE_NAME = "example.com."; // Our zone
const char* RESPONSE_IP = "1.2.3.4";

class DnsServer {
public:
    DnsServer(boost::asio::io_context& io_context)
        : socket_(io_context, udp::endpoint(udp::v4(), DNS_PORT)) {
        zone_dname_ = ldns_dname_new_frm_str(ZONE_NAME);
        if (!zone_dname_) {
            throw std::runtime_error("Failed to create zone dname");
        }
        start_receive();
        
    }
    ~DnsServer() {
        if (zone_dname_) {
            ldns_rdf_deep_free(zone_dname_);
        }
    }


private:
    ldns_rdf* zone_dname_;
    void start_receive() {
        socket_.async_receive_from(
            boost::asio::buffer(recv_buffer_), remote_endpoint_,
            [this](boost::system::error_code ec, std::size_t bytes_recvd) {
                if (!ec && bytes_recvd > 0) {
                    handle_request(bytes_recvd);
                }
                start_receive();
            });
    }

    void handle_request(std::size_t length) {
    ldns_pkt* query_pkt;
    ldns_status status = ldns_wire2pkt(&query_pkt, recv_buffer_.data(), length);
    if (status != LDNS_STATUS_OK) return;

    ldns_pkt* resp_pkt = ldns_pkt_new();
    ldns_pkt_set_id(resp_pkt, ldns_pkt_id(query_pkt));
    ldns_pkt_set_qr(resp_pkt, true); // response
    ldns_pkt_set_aa(resp_pkt, true); // authoritative
    ldns_pkt_set_ra(resp_pkt, false);

    ldns_rr_list* qlist = ldns_pkt_question(query_pkt);
    ldns_pkt_push_rr_list(resp_pkt, LDNS_SECTION_QUESTION, ldns_rr_list_clone(qlist));

    // For each question, respond with hardcoded A if in our zone
    for (size_t i = 0; i < ldns_rr_list_rr_count(qlist); ++i) {
        ldns_rr* q = ldns_rr_list_rr(qlist, i);
        ldns_rdf* qname = ldns_rr_owner(q);
        ldns_rr_type qtype = ldns_rr_get_type(q);

        if (ldns_dname_compare(qname, zone_dname_) == 0 && qtype == LDNS_RR_TYPE_A) {
            ldns_rr* a_rr = ldns_rr_new();
            ldns_rr_set_owner(a_rr, ldns_rdf_clone(qname));
            ldns_rr_set_type(a_rr, LDNS_RR_TYPE_A);
            ldns_rr_set_class(a_rr, LDNS_RR_CLASS_IN);
            ldns_rr_set_ttl(a_rr, 300); // TTL 5min

            ldns_rdf* ip_rdf;
            ldns_str2rdf_a(&ip_rdf, RESPONSE_IP);
            ldns_rr_push_rdf(a_rr, ip_rdf);

            ldns_pkt_push_rr(resp_pkt, LDNS_SECTION_ANSWER, a_rr);
        } else {
            // Not in zone → NXDOMAIN
            ldns_pkt_set_rcode(resp_pkt, LDNS_RCODE_NXDOMAIN);
        }
    }

    // Convert packet to wire format - CORRECTED
    uint8_t* resp_wire = nullptr;
    size_t resp_len;
    ldns_status wire_status = ldns_pkt2wire(&resp_wire, resp_pkt, &resp_len);

    if (wire_status == LDNS_STATUS_OK && resp_wire) {
        socket_.send_to(boost::asio::buffer(resp_wire, resp_len), remote_endpoint_);
        free(resp_wire); // Free the allocated wire data
    }

    ldns_pkt_free(query_pkt);
    ldns_pkt_free(resp_pkt);
}
    udp::socket socket_;
    udp::endpoint remote_endpoint_;
    std::array<uint8_t, 512> recv_buffer_;
};

// Global health checker for signal handling
HealthChecker* g_health_checker = nullptr;

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    if (g_health_checker) {
        g_health_checker->stop();
    }
    exit(0);
}

int main() {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    try {
        std::cout << " Starting DNS Load Balancer..." << std::endl;
        
        // Show current working directory for debugging
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != nullptr) {
            std::cout << "Current working directory: " << cwd << std::endl;
        }
        
        // Load configuration - try multiple possible locations
        std::vector<std::string> possible_config_paths = {
            "config.json",                    // Current directory
            "../config.json",                 // Parent directory
            "DNS_Load_Balancer/config.json",  // Project subdirectory
            "/home/glodh/AIORI/DNS_Load_Balancer/config.json"  // Absolute path
        };
        
        std::vector<ServerPool> pools;
        bool config_loaded = false;
        
        for (const auto& config_path : possible_config_paths) {
            std::cout << "🔍 Trying to load config from: " << config_path << std::endl;
            pools = ConfigLoader::loadBackends(config_path);
            if (!pools.empty()) {
                std::cout << " Successfully loaded config from: " << config_path << std::endl;
                config_loaded = true;
                break;
            }
        }
        
        if (!config_loaded) {
            std::cout << "  No config file found, creating default test pool..." << std::endl;
            // Create a default test pool if no config is found
            ServerPool default_pool;
            default_pool.name = "test-pool";
            default_pool.servers = {"192.168.1.100", "192.168.1.101", "192.168.99.99"}; // Include a down server
            default_pool.health_endpoint = "http://192.168.1.100/health";
            default_pool.geo_region = "us-east";
            default_pool.check_interval_sec = 10;
            pools.push_back(default_pool);
        }
        
        // Initialize and start health checker
        HealthChecker health_checker(pools);
        g_health_checker = &health_checker;
        health_checker.start();
        
        // Start DNS server
        boost::asio::io_context io_context;
        DnsServer server(io_context);
        std::cout << " DNS server started on port " << DNS_PORT << std::endl;
        std::cout << " Health checker monitoring " << pools.size() << " server pools" << std::endl;
        
        // Print initial health summary
        std::this_thread::sleep_for(std::chrono::seconds(2)); // Give health checker time to start
        health_checker.printHealthSummary();
        
        // Start DNS server threads
        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i) {
            threads.emplace_back([&io_context]() { 
                io_context.run(); 
            });
        }
        
        std::cout << " DNS Load Balancer is running! Press Ctrl+C to stop." << std::endl;
        
        // Wait for all threads
        for (auto& t : threads) {
            t.join();
        }
        
    } catch (std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << std::endl;
        if (g_health_checker) {
            g_health_checker->stop();
        }
        return 1;
    }
    
    return 0;
}
