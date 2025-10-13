#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <stdint.h>
#include "dns_lb_common.h"

#pragma pack(push, 1)

// DNS Header Structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS Resource Record
struct dns_rr {
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};

#pragma pack(pop)

// DNS Packet Parser
struct dns_parser {
    const char *packet_start;
    const char *packet_end;
    const char *current_pos;
    
    struct dns_header *header;
    char qname[MAX_DNS_NAME_LENGTH];
    uint16_t qtype;
    uint16_t qclass;
    uint8_t parse_error;
};

// Function prototypes
int parse_dns_query(struct dns_parser *parser, const char *packet_data, int packet_len);
int extract_dns_name(const char *packet_start, const char *packet_end, 
                    const char *name_ptr, char *output, int output_len);
int build_dns_response(char *buffer, int buffer_len, 
                      const struct dns_header *query_header,
                      const char *qname, uint16_t qtype, 
                      const void *rdata, int rdlength);
int build_simple_a_response(char *buffer, int buffer_len,
                           const struct dns_header *query_header,
                           const char *qname, uint32_t ip_addr);
int build_error_response(char *buffer, int buffer_len,
                        const struct dns_header *query_header,
                        uint16_t rcode);
uint64_t get_current_time_ms(void);
void print_dns_header(const struct dns_header *header);
void print_dns_question(const struct dns_parser *parser);
int validate_dns_packet(const char *packet_data, int packet_len);

#endif // DNS_PROTOCOL_H