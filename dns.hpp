#pragma once

#include <cstdint>
#include <cstring>
#include <string>

// DNS packet constants
constexpr uint16_t DNS_MAX_PACKET_SIZE = 512;
constexpr uint16_t DNS_EDNS_MAX_PACKET_SIZE = 4096;

// DNS header structure (12 bytes)
struct DNSHeader {
    uint16_t id;          // Transaction ID
    uint16_t flags;       // DNS flags
    uint16_t qdcount;     // Question count
    uint16_t ancount;     // Answer count
    uint16_t nscount;     // Authority count
    uint16_t arcount;     // Additional count
} __attribute__((packed));

// DNS question structure
struct DNSQuestion {
    char qname[256];      // Domain name (variable length)
    uint16_t qtype;       // Query type
    uint16_t qclass;      // Query class
};

// EDNS0 Client Subnet option structure
struct ECSOption {
    uint16_t family;      // Address family (1 = IPv4, 2 = IPv6)
    uint8_t source_prefix_len;
    uint8_t scope_prefix_len;
    uint8_t address[16];  // Client address (IPv4 or IPv6)
    
    ECSOption() : family(0), source_prefix_len(0), scope_prefix_len(0) {
        memset(address, 0, sizeof(address));
    }
};

// DNS parsing and manipulation functions
namespace DNS {
    // Parse DNS header from packet buffer
    bool parse_header(const uint8_t* buffer, size_t len, DNSHeader& header);
    
    // Get transaction ID from packet
    uint16_t get_transaction_id(const uint8_t* buffer);
    
    // Set transaction ID in packet
    void set_transaction_id(uint8_t* buffer, uint16_t tx_id);
    
    // Check if packet is a query (QR bit = 0)
    bool is_query(const uint8_t* buffer);
    
    // Check if packet is a response (QR bit = 1)
    bool is_response(const uint8_t* buffer);
    
    // Parse DNS question from packet
    bool parse_question(const uint8_t* buffer, size_t len, size_t& offset, DNSQuestion& question);
    
    // Check if packet has EDNS0 OPT record
    bool has_edns0(const uint8_t* buffer, size_t len);
    
    // Find and parse EDNS0 Client Subnet option
    bool find_edns_client_subnet(const uint8_t* buffer, size_t len, ECSOption& ecs);
    
    // Set response flags (QR=1, AA=0, etc.)
    void set_response_flags(uint8_t* buffer);
    
    // Validate DNS packet (basic validation)
    bool validate_packet(const uint8_t* buffer, size_t len);
    
    // Get domain name from question section
    std::string get_question_name(const uint8_t* buffer, size_t len, size_t offset = 12);
    
    // Check if response code indicates error
    bool is_error_response(const uint8_t* buffer);
    
    // Get response code (RCODE)
    uint8_t get_rcode(const uint8_t* buffer);
}

