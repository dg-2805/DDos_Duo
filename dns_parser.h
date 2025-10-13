#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "dns_protocol.h"

// Function prototypes
// Add this line with the other function prototypes
int build_simple_a_response(char *buffer, int buffer_len,
                           const struct dns_header *query_header,
                           const char *qname, uint32_t ip_addr);
int build_simple_a_response(char *buffer, int buffer_len,
                           const struct dns_header *query_header,
                           const char *qname, uint32_t ip_addr);
int extract_dns_name(const char *packet_start, const char *packet_end,
                    const char *name_ptr, char *output, int output_len);
int parse_dns_query(struct dns_parser *parser, const char *packet_data, int packet_len);
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
int validate_dns_packet(const char *packet_data, int packet_len);
void print_dns_header(const struct dns_header *header);
void print_dns_question(const struct dns_parser *parser);
uint64_t get_current_time_ms();
uint16_t calculate_udp_checksum(const void *data, int len, uint32_t src_ip, uint32_t dst_ip);

#endif // DNS_PARSER_H
