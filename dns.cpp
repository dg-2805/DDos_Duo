#include "dns.hpp"
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>

// Helper: skip a DNS name in packet buffer
static size_t skip_name(const uint8_t* buffer, size_t len, size_t offset) {
    if (offset >= len) return offset;
    
    size_t pos = offset;
    while (pos < len && buffer[pos] != 0) {
        if ((buffer[pos] & 0xC0) == 0xC0) {
            // Compression pointer
            return pos + 2;
        }
        uint8_t label_len = buffer[pos];
        pos += label_len + 1;
    }
    return pos + 1;  // +1 for null terminator
}

bool DNS::parse_header(const uint8_t* buffer, size_t len, DNSHeader& header) {
    if (len < sizeof(DNSHeader)) return false;
    
    memcpy(&header, buffer, sizeof(DNSHeader));
    // Convert from network byte order
    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qdcount = ntohs(header.qdcount);
    header.ancount = ntohs(header.ancount);
    header.nscount = ntohs(header.nscount);
    header.arcount = ntohs(header.arcount);
    
    return true;
}

uint16_t DNS::get_transaction_id(const uint8_t* buffer) {
    if (!buffer) return 0;
    uint16_t id;
    memcpy(&id, buffer, sizeof(uint16_t));
    return ntohs(id);
}

void DNS::set_transaction_id(uint8_t* buffer, uint16_t tx_id) {
    if (!buffer) return;
    uint16_t network_id = htons(tx_id);
    memcpy(buffer, &network_id, sizeof(uint16_t));
}

bool DNS::is_query(const uint8_t* buffer) {
    if (!buffer || sizeof(DNSHeader) > 512) return false;
    uint16_t flags;
    memcpy(&flags, buffer + 2, sizeof(uint16_t));
    flags = ntohs(flags);
    return (flags & 0x8000) == 0;  // QR bit = 0
}

bool DNS::is_response(const uint8_t* buffer) {
    if (!buffer) return false;
    uint16_t flags;
    memcpy(&flags, buffer + 2, sizeof(uint16_t));
    flags = ntohs(flags);
    return (flags & 0x8000) != 0;  // QR bit = 1
}

bool DNS::parse_question(const uint8_t* buffer, size_t len, size_t& offset, DNSQuestion& question) {
    if (offset >= len) return false;
    
    // Parse name
    memset(question.qname, 0, sizeof(question.qname));
    size_t name_len = 0;
    size_t pos = offset;
    
    while (pos < len && buffer[pos] != 0) {
        if ((buffer[pos] & 0xC0) == 0xC0) {
            // Compression pointer - for simplicity, don't follow it here
            pos += 2;
            break;
        }
        uint8_t label_len = buffer[pos];
        if (label_len > 63 || pos + label_len >= len) return false;
        
        if (name_len > 0 && name_len < sizeof(question.qname) - 1) {
            question.qname[name_len++] = '.';
        }
        
        pos++;
        for (uint8_t i = 0; i < label_len && pos < len && name_len < sizeof(question.qname) - 1; i++) {
            question.qname[name_len++] = buffer[pos++];
        }
    }
    
    if (pos >= len) return false;
    pos++;  // Skip null terminator
    
    // Parse QTYPE and QCLASS
    if (pos + 4 > len) return false;
    memcpy(&question.qtype, buffer + pos, sizeof(uint16_t));
    memcpy(&question.qclass, buffer + pos + 2, sizeof(uint16_t));
    question.qtype = ntohs(question.qtype);
    question.qclass = ntohs(question.qclass);
    
    offset = pos + 4;
    return true;
}

bool DNS::has_edns0(const uint8_t* buffer, size_t len) {
    DNSHeader header;
    if (!parse_header(buffer, len, header)) return false;
    
    if (header.arcount == 0) return false;
    
    // Skip questions
    size_t offset = sizeof(DNSHeader);
    for (uint16_t i = 0; i < header.qdcount && offset < len; i++) {
        offset = skip_name(buffer, len, offset);
        if (offset + 4 > len) return false;
        offset += 4;  // QTYPE + QCLASS
    }
    
    // Skip answers
    for (uint16_t i = 0; i < header.ancount && offset < len; i++) {
        offset = skip_name(buffer, len, offset);
        if (offset + 10 > len) return false;
        uint16_t rdlength;
        memcpy(&rdlength, buffer + offset + 8, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        offset += 10 + rdlength;
    }
    
    // Skip authority
    for (uint16_t i = 0; i < header.nscount && offset < len; i++) {
        offset = skip_name(buffer, len, offset);
        if (offset + 10 > len) return false;
        uint16_t rdlength;
        memcpy(&rdlength, buffer + offset + 8, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        offset += 10 + rdlength;
    }
    
    // Check additional records for OPT
    for (uint16_t i = 0; i < header.arcount && offset < len; i++) {
        if (offset >= len) break;
        
        // Check if this is an OPT record (name should be root ".")
        if (buffer[offset] == 0) {
            offset++;
            if (offset + 10 > len) break;
            
            uint16_t rtype;
            memcpy(&rtype, buffer + offset, sizeof(uint16_t));
            rtype = ntohs(rtype);
            
            if (rtype == 41) {  // OPT record type
                return true;
            }
        }
        
        offset = skip_name(buffer, len, offset);
        if (offset + 10 > len) break;
        uint16_t rdlength;
        memcpy(&rdlength, buffer + offset + 8, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        offset += 10 + rdlength;
    }
    
    return false;
}

bool DNS::find_edns_client_subnet(const uint8_t* buffer, size_t len, ECSOption& ecs) {
    DNSHeader header;
    if (!parse_header(buffer, len, header)) return false;
    
    if (header.arcount == 0) return false;
    
    // Skip questions, answers, authority
    size_t offset = sizeof(DNSHeader);
    
    for (uint16_t i = 0; i < header.qdcount && offset < len; i++) {
        offset = skip_name(buffer, len, offset);
        if (offset + 4 > len) return false;
        offset += 4;
    }
    
    for (uint16_t i = 0; i < header.ancount && offset < len; i++) {
        offset = skip_name(buffer, len, offset);
        if (offset + 10 > len) return false;
        uint16_t rdlength;
        memcpy(&rdlength, buffer + offset + 8, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        offset += 10 + rdlength;
    }
    
    for (uint16_t i = 0; i < header.nscount && offset < len; i++) {
        offset = skip_name(buffer, len, offset);
        if (offset + 10 > len) return false;
        uint16_t rdlength;
        memcpy(&rdlength, buffer + offset + 8, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        offset += 10 + rdlength;
    }
    
    // Parse additional records for OPT with ECS
    for (uint16_t i = 0; i < header.arcount && offset < len; i++) {
        if (buffer[offset] == 0) {  // Root name
            offset++;
            if (offset + 11 > len) break;
            
            uint16_t rtype;
            memcpy(&rtype, buffer + offset, sizeof(uint16_t));
            rtype = ntohs(rtype);
            
            if (rtype == 41) {  // OPT record
                offset += 2;  // Skip QCLASS (UDP payload size)
                uint8_t extended_rcode, version;
                memcpy(&extended_rcode, buffer + offset, 1);
                memcpy(&version, buffer + offset + 1, 1);
                offset += 4;  // Skip extended RCODE, version, flags
                
                uint16_t rdlength;
                memcpy(&rdlength, buffer + offset, sizeof(uint16_t));
                rdlength = ntohs(rdlength);
                offset += 2;
                
                // Parse EDNS options
                size_t opt_end = offset + rdlength;
                while (offset + 4 <= opt_end) {
                    uint16_t opt_code, opt_len;
                    memcpy(&opt_code, buffer + offset, sizeof(uint16_t));
                    memcpy(&opt_len, buffer + offset + 2, sizeof(uint16_t));
                    opt_code = ntohs(opt_code);
                    opt_len = ntohs(opt_len);
                    offset += 4;
                    
                    if (opt_code == 8) {  // EDNS Client Subnet
                        if (offset + opt_len > opt_end || opt_len < 4) break;
                        
                        uint16_t family;
                        memcpy(&family, buffer + offset, sizeof(uint16_t));
                        family = ntohs(family);
                        
                        ecs.family = family;
                        ecs.source_prefix_len = buffer[offset + 2];
                        ecs.scope_prefix_len = buffer[offset + 3];
                        
                        size_t addr_bytes = (ecs.source_prefix_len + 7) / 8;
                        if (addr_bytes > 16) addr_bytes = 16;
                        memset(ecs.address, 0, 16);
                        if (offset + 4 + addr_bytes <= opt_end) {
                            memcpy(ecs.address, buffer + offset + 4, addr_bytes);
                        }
                        
                        return true;
                    }
                    
                    offset += opt_len;
                }
            }
        }
        
        offset = skip_name(buffer, len, offset);
        if (offset + 10 > len) break;
        uint16_t rdlength;
        memcpy(&rdlength, buffer + offset + 8, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        offset += 10 + rdlength;
    }
    
    return false;
}

void DNS::set_response_flags(uint8_t* buffer) {
    if (!buffer) return;
    uint16_t flags;
    memcpy(&flags, buffer + 2, sizeof(uint16_t));
    flags = ntohs(flags);
    flags |= 0x8000;  // Set QR bit
    flags = htons(flags);
    memcpy(buffer + 2, &flags, sizeof(uint16_t));
}

bool DNS::validate_packet(const uint8_t* buffer, size_t len) {
    if (!buffer || len < sizeof(DNSHeader)) return false;
    if (len > DNS_EDNS_MAX_PACKET_SIZE) return false;
    
    DNSHeader header;
    if (!parse_header(buffer, len, header)) return false;
    
    // Basic validation: check for reasonable question count
    if (header.qdcount > 100) return false;
    
    return true;
}

std::string DNS::get_question_name(const uint8_t* buffer, size_t len, size_t offset) {
    if (offset >= len) return "";
    
    std::string name;
    size_t pos = offset;
    
    while (pos < len && buffer[pos] != 0) {
        if ((buffer[pos] & 0xC0) == 0xC0) {
            // Compression - simplified handling
            break;
        }
        
        uint8_t label_len = buffer[pos];
        if (label_len > 63 || pos + label_len >= len) break;
        
        pos++;
        if (!name.empty()) name += ".";
        for (uint8_t i = 0; i < label_len && pos < len; i++) {
            name += static_cast<char>(buffer[pos++]);
        }
    }
    
    return name;
}

bool DNS::is_error_response(const uint8_t* buffer) {
    if (!buffer) return false;
    uint16_t flags;
    memcpy(&flags, buffer + 2, sizeof(uint16_t));
    flags = ntohs(flags);
    uint8_t rcode = flags & 0x0F;
    return rcode != 0;
}

uint8_t DNS::get_rcode(const uint8_t* buffer) {
    if (!buffer) return 0;
    uint16_t flags;
    memcpy(&flags, buffer + 2, sizeof(uint16_t));
    flags = ntohs(flags);
    return flags & 0x0F;
}

