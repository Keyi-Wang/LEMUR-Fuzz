
#ifndef DNS_H
#define DNS_H

#include "dns_packets.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint8_t u8;

#ifdef __cplusplus
extern "C" {
#endif

dns_packet_t *generate_dns_packets(int count);

size_t parse_dns_msg(const uint8_t *buf, u32 buf_len,
                    dns_packet_t *out_packets, u32 max_count);

void fix_dns(dns_packet_t *pkt, int num_packets);

void dispatch_dns_mutation(dns_packet_t *pkts, unsigned int pkt_count);
void dispatch_dns_multiple_mutations(dns_packet_t *pkts, unsigned int pkt_count,
                                     unsigned int rounds);

int reassemble_dns_msgs(const dns_packet_t *packets, u32 num_packets,
                        u8 *output_buf, u32 *out_len);

void print_dns_packets(const dns_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif /* DNS_H */
