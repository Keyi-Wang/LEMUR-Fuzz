
#ifndef DICOM_H
#define DICOM_H

#include "dicom_packets.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint8_t u8;

#ifdef __cplusplus
extern "C" {
#endif

dicom_packet_t *generate_dicom_packets(int count);

size_t parse_dicom_msg(const uint8_t *buf, u32 buf_len,
                    dicom_packet_t *out_packets, u32 max_count);

void fix_dicom(dicom_packet_t *pkt, int num_packets);
void dispatch_dicom_multiple_mutations(dicom_packet_t *pkts, int num_packets, int rounds);

int reassemble_dicom_msgs(const dicom_packet_t *packets, u32 num_packets,
                        u8 *output_buf, u32 *out_len);

void print_dicom_packets(const dicom_packet_t *packets, int count);

#ifdef __cplusplus
}
#endif

#endif /* DICOM_H */
