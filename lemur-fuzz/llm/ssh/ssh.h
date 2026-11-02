
#ifndef SSH_H
#define SSH_H

#include "ssh_packets.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint8_t u8;

#ifdef __cplusplus
extern "C" {
#endif

ssh_packet_t *generate_ssh_packets(int count);

size_t parse_ssh_msg(const uint8_t *buf, u32 buf_len,
                    ssh_packet_t *out_packets, u32 max_count);

void fix_ssh(ssh_packet_t *pkt, int num_packets);

void dispatch_ssh_mutation(ssh_packet_t *pkts, unsigned int pkt_count);
void dispatch_ssh_multiple_mutations(ssh_packet_t *pkts, unsigned int pkt_count,
                                     unsigned int rounds);

int reassemble_ssh_msgs(const ssh_packet_t *packets, u32 num_packets,
                        u8 *output_buf, u32 *out_len);

void print_ssh_packets(const ssh_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif /* SSH_H */
