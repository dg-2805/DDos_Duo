#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include "dns_parser.h"
#include "dns_lb_common.h"
#include "dns_protocol.h"

static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

// Generate random A record response
uint32_t generate_random_ip(void) {
    return htonl(0x7F000001 + (rand() % 10)); // 127.0.0.1-127.0.0.10
}

// Handle DNS query
void handle_dns_query(int sockfd, const char *buffer, int len, 
                     struct sockaddr_in *client_addr, socklen_t client_len) {
    struct dns_parser parser;
    char response_buffer[512];
    
    if (parse_dns_query(&parser, buffer, len) != 0) {
        printf("Failed to parse DNS query\n");
        return;
    }
    
    printf("Received query for: %s (type: %d)\n", parser.qname, parser.qtype);
    
    // Simulate some latency (0-50ms)
    int latency_ms = rand() % 50;
    if (latency_ms > 0) {
        usleep(latency_ms * 1000);
    }
    
    // Simulate occasional failure (5% chance)
    if (rand() % 100 < 5) {
        printf("Simulating backend failure for: %s\n", parser.qname);
        return; // Drop packet to simulate failure
    }
    
    // Build response
    uint32_t ip_addr = generate_random_ip();
    int response_len = build_simple_a_response(response_buffer, sizeof(response_buffer),
                                             parser.header, parser.qname, ip_addr);
    
    if (response_len > 0) {
        sendto(sockfd, response_buffer, response_len, 0,
               (struct sockaddr*)client_addr, client_len);
        printf("Sent response for: %s -> %d.%d.%d.%d\n", parser.qname,
               (ip_addr >> 24) & 0xFF, (ip_addr >> 16) & 0xFF,
               (ip_addr >> 8) & 0xFF, ip_addr & 0xFF);
    }
}

// DNS server worker
void* dns_server_worker(void *arg) {
    uint16_t port = *(uint16_t*)arg;
    int sockfd;
    struct sockaddr_in server_addr;
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }
    
    // Set SO_REUSEADDR
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    // Bind to port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return NULL;
    }
    
    printf("Mock DNS server listening on port %d\n", port);
    
    // Main server loop
    while (running) {
        char buffer[512];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        ssize_t received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&client_addr, &client_len);
        
        if (received > 0) {
            handle_dns_query(sockfd, buffer, received, &client_addr, client_len);
        }
    }
    
    close(sockfd);
    printf("Mock DNS server on port %d stopped\n", port);
    return NULL;
}

int main(int argc, char *argv[]) {
    uint16_t port = 5353;
    char *ip_str = "127.0.0.1";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            ip_str = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--port PORT] [--ip IP]\n", argv[0]);
            return 0;
        }
    }
    
    printf("Starting mock DNS server on %s:%d\n", ip_str, port);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    srand(time(NULL));
    
    // For simplicity, we'll just run one server in this process
    // In real testing, you'd run multiple instances on different ports
    dns_server_worker(&port);
    
    return 0;
}
