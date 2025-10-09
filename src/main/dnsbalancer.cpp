#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

class DNSBalancer {
private:
    int server_socket;
    struct sockaddr_in server_addr;

    // Simple DNS response builder
    void buildDNSResponse(const char* query, int query_len, char* response, int* response_len) {
        // Copy the query header (first 12 bytes)
        memcpy(response, query, 12);
        
        // Set the QR bit to indicate this is a RESPONSE (bit 7 of byte 2)
        response[2] = 0x81; // Response + No error
        response[3] = 0x80; // Standard query response
        
        // Copy the question section
        memcpy(response + 12, query + 12, query_len - 12);
        
        // Add answer section (hardcoded for now)
        // Point to the domain name in question section (with compression)
        response[query_len] = 0xC0; // Compression pointer
        response[query_len + 1] = 0x0C; // Points to position 12
        
        // Type A record (host address)
        response[query_len + 2] = 0x00;
        response[query_len + 3] = 0x01;
        
        // Class IN (Internet)
        response[query_len + 4] = 0x00;
        response[query_len + 5] = 0x01;
        
        // TTL (4 bytes) - 300 seconds
        response[query_len + 6] = 0x00;
        response[query_len + 7] = 0x00;
        response[query_len + 8] = 0x01;
        response[query_len + 9] = 0x2C;
        
        // Data length (2 bytes) - 4 for IPv4
        response[query_len + 10] = 0x00;
        response[query_len + 11] = 0x04;
        
        // IP address (hardcoded to 8.8.8.8 for testing)
        response[query_len + 12] = 0x08;
        response[query_len + 13] = 0x08;
        response[query_len + 14] = 0x08;
        response[query_len + 15] = 0x08;
        
        *response_len = query_len + 16;
    }

public:
    bool start() {
        // Create UDP socket
        server_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_socket < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        // Configure server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(5353);  // Development port

        // Bind socket
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Bind failed" << std::endl;
            close(server_socket);
            return false;
        }

        std::cout << "🚀 DNS Load Balancer listening on port 5353..." << std::endl;
        return true;
    }

    void run() {
        char buffer[512];
        char response[512];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        while (true) {
            // Receive DNS query
            ssize_t bytes_received = recvfrom(server_socket, buffer, sizeof(buffer), 0,
                                            (struct sockaddr*)&client_addr, &client_len);
            
            if (bytes_received > 0) {
                std::cout << "📨 Received " << bytes_received << " bytes from ";
                std::cout << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
                
                // Build proper DNS response
                int response_len;
                buildDNSResponse(buffer, bytes_received, response, &response_len);
                
                // Send DNS response
                sendto(server_socket, response, response_len, 0,
                      (struct sockaddr*)&client_addr, client_len);
                
                std::cout << "✅ Sent DNS response with 8.8.8.8" << std::endl;
            }
        }
    }

    ~DNSBalancer() {
        if (server_socket >= 0) {
            close(server_socket);
        }
    }
};

int main() {
    DNSBalancer balancer;
    
    if (!balancer.start()) {
        return 1;
    }

    balancer.run();
    return 0;
}