
#ifndef TLS_H
#define TLS_H

#include "tls_packets.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint8_t u8;

#ifdef __cplusplus
extern "C" {
#endif

tls_packet_t *generate_tls_packets(int count);

size_t parse_tls_msg(const uint8_t *buf, u32 buf_len,
                    tls_packet_t *out_packets, u32 max_count);

void fix_tls(tls_packet_t *pkt, int num_packets);
void dispatch_tls_multiple_mutations(tls_packet_t *pkts, int num_packets, int rounds);

int reassemble_tls_msgs(const tls_packet_t *packets, u32 num_packets,
                        u8 *output_buf, u32 *out_len);

void print_tls_packets(const tls_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif /* TLS_H */
