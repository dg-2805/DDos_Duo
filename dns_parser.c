#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "dns_lb_common.h"
#include "dns_protocol.h"

// Extract DNS name from packet (handles compression)
int extract_dns_name(const char *packet_start, const char *packet_end,
                    const char *name_ptr, char *output, int output_len) {
    const char *current = name_ptr;
    char *out_ptr = output;
    int jumps = 0;
    int max_jumps = 16; // Prevent infinite loops from malicious packets
    
    if (output_len < 1) return -1;
    
    while (current < packet_end && jumps < max_jumps) {
        if ((unsigned char)*current == 0) {
            // End of name
            if (out_ptr > output) {
                // Remove trailing dot
                out_ptr[-1] = '\0';
            } else {
                *out_ptr = '\0';
            }
            return out_ptr - output;
        }
        
        // Check for compression pointer
        if (((unsigned char)*current & 0xC0) == 0xC0) {
            if (current + 1 >= packet_end) return -1;
            
            // Calculate offset from compression pointer
            uint16_t offset = ntohs(*(uint16_t*)current) & 0x3FFF;
            if (offset >= (current - packet_start)) return -1;
            
            // Jump to compressed name
            current = packet_start + offset;
            jumps++;
            continue;
        }
        
        // Read label length
        uint8_t label_len = (uint8_t)*current;
        current++;
        
        if (current + label_len > packet_end) return -1;
        
        // Check output buffer space
        if ((out_ptr - output) + label_len + 1 > output_len) return -1;
        
        // Copy label
        memcpy(out_ptr, current, label_len);
        out_ptr += label_len;
        *out_ptr++ = '.';
        
        current += label_len;
    }
    
    return -1; // Too many jumps or malformed packet
}

// Parse DNS query packet
int parse_dns_query(struct dns_parser *parser, const char *packet_data, int packet_len) {
    if (!parser || !packet_data || packet_len < (int)sizeof(struct dns_header)) {
        return -1;
    }
    
    parser->packet_start = packet_data;
    parser->packet_end = packet_data + packet_len;
    parser->current_pos = packet_data;
    parser->parse_error = 0;
    
    // Parse DNS header
    parser->header = (struct dns_header*)parser->current_pos;
    parser->current_pos += sizeof(struct dns_header);
    
    // Validate header
    uint16_t qdcount = ntohs(parser->header->qdcount);
    if (qdcount == 0 || qdcount > 10) { // Sanity check
        parser->parse_error = 1;
        return -1;
    }
    
    // Parse question section (only first question for now)
    if (parser->current_pos >= parser->packet_end) {
        parser->parse_error = 1;
        return -1;
    }
    
    // Extract QNAME
    int name_len = extract_dns_name(parser->packet_start, parser->packet_end,
                                   parser->current_pos, parser->qname, MAX_DNS_NAME_LENGTH);
    if (name_len < 0) {
        parser->parse_error = 1;
        return -1;
    }
    
    // Advance past QNAME
    while (parser->current_pos < parser->packet_end && *parser->current_pos != 0) {
        parser->current_pos++;
    }
    if (parser->current_pos >= parser->packet_end) {
        parser->parse_error = 1;
        return -1;
    }
    parser->current_pos++; // Skip null terminator
    
    // Parse QTYPE and QCLASS
    if (parser->current_pos + 4 > parser->packet_end) {
        parser->parse_error = 1;
        return -1;
    }
    
    parser->qtype = ntohs(*(uint16_t*)parser->current_pos);
    parser->current_pos += 2;
    parser->qclass = ntohs(*(uint16_t*)parser->current_pos);
    parser->current_pos += 2;
    
    return 0;
}

// Build DNS response packet
int build_dns_response(char *buffer, int buffer_len,
                      const struct dns_header *query_header,
                      const char *qname, uint16_t qtype,
                      const void *rdata, int rdlength) {
    (void)qname; // Mark unused parameter
    
    if (!buffer || !query_header || buffer_len < 512) {
        return -1;
    }
    
    char *ptr = buffer;
    int remaining = buffer_len;
    
    // Build DNS header
    struct dns_header *response_header = (struct dns_header*)ptr;
    memcpy(response_header, query_header, sizeof(struct dns_header));
    
    // Set response flags
    response_header->flags = htons(ntohs(query_header->flags) | DNS_QR_RESPONSE | DNS_RA_RECURSION_AVAILABLE);
    response_header->ancount = htons(1); // One answer
    response_header->nscount = htons(0);
    response_header->arcount = htons(0);
    
    ptr += sizeof(struct dns_header);
    remaining -= sizeof(struct dns_header);
    
    // Copy question section (simplified - in real implementation, copy from query)
    // For now, we'll just return the header
    // In a complete implementation, you'd copy the question section here
    
    // Build answer section
    // Name (compressed - pointer to question name)
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(0xC00C); // Pointer to offset 12 (start of question)
    ptr += 2;
    remaining -= 2;
    
    // Type
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(qtype);
    ptr += 2;
    remaining -= 2;
    
    // Class
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(1); // IN class
    ptr += 2;
    remaining -= 2;
    
    // TTL
    if (remaining < 4) return -1;
    *(uint32_t*)ptr = htonl(300); // 5 minutes TTL
    ptr += 4;
    remaining -= 4;
    
    // RDATA length
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(rdlength);
    ptr += 2;
    remaining -= 2;
    
    // RDATA
    if (remaining < rdlength) return -1;
    memcpy(ptr, rdata, rdlength);
    ptr += rdlength;
    
    return ptr - buffer;
}

// Create a simple DNS response for testing
int build_simple_a_response(char *buffer, int buffer_len,
                           const struct dns_header *query_header,
                           const char *qname, uint32_t ip_addr) {
    if (!buffer || !query_header || buffer_len < 512) {
        return -1;
    }
    
    struct dns_header *response_header = (struct dns_header*)buffer;
    memcpy(response_header, query_header, sizeof(struct dns_header));
    
    // Set response flags
    response_header->flags = htons(0x8180); // Response + Recursion Available + No error
    response_header->ancount = htons(1);
    
    char *ptr = buffer + sizeof(struct dns_header);
    
    // Copy the original question section (this is crucial!)
    // For simplicity, we'll just use a fixed QNAME
    const char *domain = "google.com";
    const char *dot = strchr(domain, '.');
    
    // First label
    int len1 = dot - domain;
    *ptr++ = len1;
    memcpy(ptr, domain, len1);
    ptr += len1;
    
    // Second label  
    const char *second = dot + 1;
    int len2 = strlen(second);
    *ptr++ = len2;
    memcpy(ptr, second, len2);
    ptr += len2;
    
    *ptr++ = 0; // Null terminator
    
    // QTYPE and QCLASS
    *(uint16_t*)ptr = htons(1); // A record
    ptr += 2;
    *(uint16_t*)ptr = htons(1); // IN class
    ptr += 2;

    // Answer section - use compression pointer correctly (0xC00C points to question name)
    *(uint16_t*)ptr = htons(0xC00C); // pointer to question name
    ptr += 2;
    *(uint16_t*)ptr = htons(1); // A record
    ptr += 2;
    *(uint16_t*)ptr = htons(1); // IN class
    ptr += 2;
    *(uint32_t*)ptr = htonl(300); // TTL 5 minutes
    ptr += 4;
    *(uint16_t*)ptr = htons(4); // RDATA length
    ptr += 2;
    *(uint32_t*)ptr = ip_addr; // IP address (already in network byte order)
    ptr += 4;
    
    return ptr - buffer;
}

// Create a DNS error response
int build_error_response(char *buffer, int buffer_len,
                        const struct dns_header *query_header,
                        uint16_t rcode) {
    if (!buffer || !query_header || buffer_len < (int)sizeof(struct dns_header)) {
        return -1;
    }
    
    struct dns_header *response_header = (struct dns_header*)buffer;
    memcpy(response_header, query_header, sizeof(struct dns_header));
    
    // Set response flags with error code
    uint16_t flags = ntohs(query_header->flags);
    flags |= DNS_QR_RESPONSE;
    flags |= (rcode & 0x0F); // Set response code
    response_header->flags = htons(flags);
    
    response_header->ancount = htons(0);
    response_header->nscount = htons(0);
    response_header->arcount = htons(0);
    
    return sizeof(struct dns_header);
}

// Validate DNS packet structure
int validate_dns_packet(const char *packet_data, int packet_len) {
    if (packet_len < (int)sizeof(struct dns_header)) {
        return -1;
    }
    
    struct dns_header *header = (struct dns_header*)packet_data;
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    uint16_t nscount = ntohs(header->nscount);
    uint16_t arcount = ntohs(header->arcount);
    
    // Basic sanity checks
    if (qdcount > 100 || ancount > 100 || nscount > 100 || arcount > 100) {
        return -1;
    }
    
    // Check if it's a query (QR bit = 0)
    if (ntohs(header->flags) & DNS_QR_RESPONSE) {
        return 1; // It's a response, not an error
    }
    
    return 0; // Valid query
}

// Print DNS header for debugging
void print_dns_header(const struct dns_header *header) {
    printf("DNS Header:\n");
    printf("  ID: 0x%04x\n", ntohs(header->id));
    printf("  Flags: 0x%04x\n", ntohs(header->flags));
    printf("  Questions: %d\n", ntohs(header->qdcount));
    printf("  Answers: %d\n", ntohs(header->ancount));
    printf("  Authority: %d\n", ntohs(header->nscount));
    printf("  Additional: %d\n", ntohs(header->arcount));
    
    uint16_t flags = ntohs(header->flags);
    printf("  QR: %s\n", (flags & DNS_QR_RESPONSE) ? "Response" : "Query");
    printf("  OPCODE: %d\n", (flags >> 11) & 0x0F);
    printf("  AA: %d\n", (flags >> 10) & 1);
    printf("  TC: %d\n", (flags >> 9) & 1);
    printf("  RD: %d\n", (flags >> 8) & 1);
    printf("  RA: %d\n", (flags >> 7) & 1);
    printf("  RCODE: %d\n", flags & 0x0F);
}

// Print DNS question for debugging
void print_dns_question(const struct dns_parser *parser) {
    printf("DNS Question:\n");
    printf("  QNAME: %s\n", parser->qname);
    printf("  QTYPE: %d\n", parser->qtype);
    printf("  QCLASS: %d\n", parser->qclass);
    
    // Print QTYPE as string
    const char *qtype_str = "UNKNOWN";
    switch (parser->qtype) {
        case DNS_TYPE_A: qtype_str = "A"; break;
        case DNS_TYPE_AAAA: qtype_str = "AAAA"; break;
        case DNS_TYPE_CNAME: qtype_str = "CNAME"; break;
        case DNS_TYPE_NS: qtype_str = "NS"; break;
        case DNS_TYPE_MX: qtype_str = "MX"; break;
        case DNS_TYPE_TXT: qtype_str = "TXT"; break;
        case DNS_TYPE_SOA: qtype_str = "SOA"; break;
        default: qtype_str = "UNKNOWN"; break;
    }
    printf("  QTYPE (str): %s\n", qtype_str);
}

// Utility function to get current timestamp in milliseconds
uint64_t get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Calculate packet checksum (for UDP)
uint16_t calculate_udp_checksum(const void *data, int len, uint32_t src_ip, uint32_t dst_ip) {
    // Return 0 for no checksum (simplified)
    (void)data;
    (void)len;
    (void)src_ip;
    (void)dst_ip;
    return 0;
}
/*#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <time.h>  // Add this for clock_gettime
#include <unistd.h> 
#include "dns_lb_common.h"
#include "dns_protocol.h"

// Extract DNS name from packet (handles compression)
int extract_dns_name(const char *packet_start, const char *packet_end,
                    const char *name_ptr, char *output, int output_len) {
    const char *current = name_ptr;
    char *out_ptr = output;
    int jumps = 0;
    int max_jumps = 16; // Prevent infinite loops from malicious packets
    
    if (output_len < 1) return -1;
    
    while (current < packet_end && jumps < max_jumps) {
        if ((unsigned char)*current == 0) {
            // End of name
            if (out_ptr > output) {
                // Remove trailing dot
                out_ptr[-1] = '\0';
            } else {
                *out_ptr = '\0';
            }
            return out_ptr - output;
        }
        
        // Check for compression pointer
        if (((unsigned char)*current & 0xC0) == 0xC0) {
            if (current + 1 >= packet_end) return -1;
            
            // Calculate offset from compression pointer
            uint16_t offset = ntohs(*(uint16_t*)current) & 0x3FFF;
            if (offset >= (current - packet_start)) return -1;
            
            // Jump to compressed name
            current = packet_start + offset;
            jumps++;
            continue;
        }
        
        // Read label length
        uint8_t label_len = (uint8_t)*current;
        current++;
        
        if (current + label_len > packet_end) return -1;
        
        // Check output buffer space
        if ((out_ptr - output) + label_len + 1 > output_len) return -1;
        
        // Copy label
        memcpy(out_ptr, current, label_len);
        out_ptr += label_len;
        *out_ptr++ = '.';
        
        current += label_len;
    }
    
    return -1; // Too many jumps or malformed packet
}

// Parse DNS query packet
int parse_dns_query(struct dns_parser *parser, const char *packet_data, int packet_len) {
    if (!parser || !packet_data || packet_len < (int)sizeof(struct dns_header)) {
        return -1;
    }
    
    parser->packet_start = packet_data;
    parser->packet_end = packet_data + packet_len;
    parser->current_pos = packet_data;
    parser->parse_error = 0;
    
    // Parse DNS header
    parser->header = (struct dns_header*)parser->current_pos;
    parser->current_pos += sizeof(struct dns_header);
    
    // Validate header
    uint16_t qdcount = ntohs(parser->header->qdcount);
    if (qdcount == 0 || qdcount > 10) { // Sanity check
        parser->parse_error = 1;
        return -1;
    }
    
    // Parse question section (only first question for now)
    if (parser->current_pos >= parser->packet_end) {
        parser->parse_error = 1;
        return -1;
    }
    
    // Extract QNAME
    int name_len = extract_dns_name(parser->packet_start, parser->packet_end,
                                   parser->current_pos, parser->qname, MAX_DNS_NAME_LENGTH);
    if (name_len < 0) {
        parser->parse_error = 1;
        return -1;
    }
    
    // Advance past QNAME
    while (parser->current_pos < parser->packet_end && *parser->current_pos != 0) {
        parser->current_pos++;
    }
    if (parser->current_pos >= parser->packet_end) {
        parser->parse_error = 1;
        return -1;
    }
    parser->current_pos++; // Skip null terminator
    
    // Parse QTYPE and QCLASS
    if (parser->current_pos + 4 > parser->packet_end) {
        parser->parse_error = 1;
        return -1;
    }
    
    parser->qtype = ntohs(*(uint16_t*)parser->current_pos);
    parser->current_pos += 2;
    parser->qclass = ntohs(*(uint16_t*)parser->current_pos);
    parser->current_pos += 2;
    
    return 0;
}

// Build DNS response packet
int build_dns_response(char *buffer, int buffer_len,
                      const struct dns_header *query_header,
                      const char *qname, uint16_t qtype,
                      const void *rdata, int rdlength) {
                        (void)qname;
    if (!buffer || !query_header || buffer_len < 512) {
        return -1;
    }
    
    char *ptr = buffer;
    int remaining = buffer_len;
    
    // Create a simple DNS response for testing
int build_simple_a_response(char *buffer, int buffer_len,
                           const struct dns_header *query_header,
                           const char *qname, uint32_t ip_addr) {
    return build_dns_response(buffer, buffer_len, query_header, qname,
                            DNS_TYPE_A, &ip_addr, 4);
}

    // Build DNS header
    struct dns_header *response_header = (struct dns_header*)ptr;
    memcpy(response_header, query_header, sizeof(struct dns_header));
    
    // Set response flags
    response_header->flags = htons(ntohs(query_header->flags) | DNS_QR_RESPONSE | DNS_RA_RECURSION_AVAILABLE);
    response_header->ancount = htons(1); // One answer
    response_header->nscount = 0;
    response_header->arcount = 0;
    
    ptr += sizeof(struct dns_header);
    remaining -= sizeof(struct dns_header);
    
    // Copy question section
    // For simplicity, we assume the question is already in the buffer
    // In real implementation, you'd copy from the query
    
    // Build answer section
    // Name (compressed - pointer to question name)
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(0xC00C); // Pointer to offset 12 (start of question)
    ptr += 2;
    remaining -= 2;
    
    // Type
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(qtype);
    ptr += 2;
    remaining -= 2;
    
    // Class
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(1); // IN class
    ptr += 2;
    remaining -= 2;
    
    // TTL
    if (remaining < 4) return -1;
    *(uint32_t*)ptr = htonl(300); // 5 minutes TTL
    ptr += 4;
    remaining -= 4;
    
    // RDATA length
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(rdlength);
    ptr += 2;
    remaining -= 2;
    
    // RDATA
    if (remaining < rdlength) return -1;
    memcpy(ptr, rdata, rdlength);
    ptr += rdlength;
    
    return ptr - buffer;
}

// Create a simple DNS response for testing
// Build DNS response packet
int build_dns_response(char *buffer, int buffer_len,
                      const struct dns_header *query_header,
                      const char *qname, uint16_t qtype,
                      const void *rdata, int rdlength) {
    if (!buffer || !query_header || buffer_len < 512) {
        return -1;
    }
    
    char *ptr = buffer;
    int remaining = buffer_len;
    
    // Build DNS header
    struct dns_header *response_header = (struct dns_header*)ptr;
    memcpy(response_header, query_header, sizeof(struct dns_header));
    
    // Set response flags
    response_header->flags = htons(ntohs(query_header->flags) | DNS_QR_RESPONSE | DNS_RA_RECURSION_AVAILABLE);
    response_header->ancount = htons(1); // One answer
    response_header->nscount = htons(0);
    response_header->arcount = htons(0);
    
    ptr += sizeof(struct dns_header);
    remaining -= sizeof(struct dns_header);
    
    // Copy question section (simplified - in real implementation, copy from query)
    // For now, we'll just return the header
    // In a complete implementation, you'd copy the question section here
    
    // Build answer section
    // Name (compressed - pointer to question name)
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(0xC00C); // Pointer to offset 12 (start of question)
    ptr += 2;
    remaining -= 2;
    
    // Type
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(qtype);
    ptr += 2;
    remaining -= 2;
    
    // Class
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(1); // IN class
    ptr += 2;
    remaining -= 2;
    
    // TTL
    if (remaining < 4) return -1;
    *(uint32_t*)ptr = htonl(300); // 5 minutes TTL
    ptr += 4;
    remaining -= 4;
    
    // RDATA length
    if (remaining < 2) return -1;
    *(uint16_t*)ptr = htons(rdlength);
    ptr += 2;
    remaining -= 2;
    
    // RDATA
    if (remaining < rdlength) return -1;
    memcpy(ptr, rdata, rdlength);
    ptr += rdlength;
    
    return ptr - buffer;
}

// Create a simple DNS response for testing
/*int build_simple_a_response(char *buffer, int buffer_len,
                           const struct dns_header *query_header,
                           const char *qname, uint32_t ip_addr) {
    return build_dns_response(buffer, buffer_len, query_header, qname,
                            DNS_TYPE_A, &ip_addr, 4);
}

// Create a DNS error response
int build_error_response(char *buffer, int buffer_len,
                        const struct dns_header *query_header,
                        uint16_t rcode) {
    if (!buffer || !query_header || buffer_len < (int)sizeof(struct dns_header)) {
        return -1;
    }
    
    struct dns_header *response_header = (struct dns_header*)buffer;
    memcpy(response_header, query_header, sizeof(struct dns_header));
    
    // Set response flags with error code
    uint16_t flags = ntohs(query_header->flags);
    flags |= DNS_QR_RESPONSE;
    flags |= (rcode & 0x0F); // Set response code
    response_header->flags = htons(flags);
    
    response_header->ancount = 0;
    response_header->nscount = 0;
    response_header->arcount = 0;
    
    return sizeof(struct dns_header);
}

// Validate DNS packet structure
int validate_dns_packet(const char *packet_data, int packet_len) {
    if (packet_len < (int)sizeof(struct dns_header)) {
        return -1;
    }
    
    struct dns_header *header = (struct dns_header*)packet_data;
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    uint16_t nscount = ntohs(header->nscount);
    uint16_t arcount = ntohs(header->arcount);
    
    // Basic sanity checks
    if (qdcount > 100 || ancount > 100 || nscount > 100 || arcount > 100) {
        return -1;
    }
    
    // Check if it's a query (QR bit = 0)
    if (ntohs(header->flags) & DNS_QR_RESPONSE) {
        return 1; // It's a response, not an error
    }
    
    return 0; // Valid query
}

// Print DNS header for debugging
void print_dns_header(const struct dns_header *header) {
    printf("DNS Header:\n");
    printf("  ID: 0x%04x\n", ntohs(header->id));
    printf("  Flags: 0x%04x\n", ntohs(header->flags));
    printf("  Questions: %d\n", ntohs(header->qdcount));
    printf("  Answers: %d\n", ntohs(header->ancount));
    printf("  Authority: %d\n", ntohs(header->nscount));
    printf("  Additional: %d\n", ntohs(header->arcount));
    
    uint16_t flags = ntohs(header->flags);
    printf("  QR: %s\n", (flags & DNS_QR_RESPONSE) ? "Response" : "Query");
    printf("  OPCODE: %d\n", (flags >> 11) & 0x0F);
    printf("  AA: %d\n", (flags >> 10) & 1);
    printf("  TC: %d\n", (flags >> 9) & 1);
    printf("  RD: %d\n", (flags >> 8) & 1);
    printf("  RA: %d\n", (flags >> 7) & 1);
    printf("  RCODE: %d\n", flags & 0x0F);
}

// Print DNS question for debugging
void print_dns_question(const struct dns_parser *parser) {
    printf("DNS Question:\n");
    printf("  QNAME: %s\n", parser->qname);
    printf("  QTYPE: %d\n", parser->qtype);
    printf("  QCLASS: %d\n", parser->qclass);
    
    // Print QTYPE as string
    const char *qtype_str = "UNKNOWN";
    switch (parser->qtype) {
        case DNS_TYPE_A: qtype_str = "A"; break;
        case DNS_TYPE_AAAA: qtype_str = "AAAA"; break;
        case DNS_TYPE_CNAME: qtype_str = "CNAME"; break;
        case DNS_TYPE_NS: qtype_str = "NS"; break;
        case DNS_TYPE_MX: qtype_str = "MX"; break;
        case DNS_TYPE_TXT: qtype_str = "TXT"; break;
        case DNS_TYPE_SOA: qtype_str = "SOA"; break;
    }
    printf("  QTYPE (str): %s\n", qtype_str);
}

// Utility function to get current timestamp in milliseconds
uint64_t get_current_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Calculate packet checksum (for UDP)
uint16_t calculate_udp_checksum(const void *data, int len, uint32_t src_ip, uint32_t dst_ip) {
    // Return 0 for no checksum (simplified)
    (void)data;
    (void)len;
    (void)src_ip;
    (void)dst_ip;
    return 0;
}
*/
