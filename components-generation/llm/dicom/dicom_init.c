#include "dicom.h"
#include <stdlib.h>

dicom_packet_t *generate_dicom_packets(int count) {
  if (count <= 0) return NULL;
  dicom_packet_t *pkts = (dicom_packet_t *)calloc((size_t)count, sizeof(dicom_packet_t));
  if (!pkts) return NULL;
  for (int i = 0; i < count; ++i) {
    pkts[i].packet_type = DICOM_PDU_PACKET;
    pkts[i].pdu_type = 0x01;
    pkts[i].reserved = 0;
    pkts[i].length = 0;
    pkts[i].payload_len = 0;
  }
  return pkts;
}
