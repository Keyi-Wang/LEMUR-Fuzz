#include "tls.h"
#include <stdlib.h>
#include <string.h>

tls_packet_t *generate_tls_packets(int count) {
  if (count <= 0) return NULL;
  tls_packet_t *pkts = (tls_packet_t *)calloc((size_t)count, sizeof(tls_packet_t));
  if (!pkts) return NULL;
  for (int i = 0; i < count; ++i) {
    pkts[i].packet_type = TLS_RECORD_PACKET;
    pkts[i].content_type = 22;
    pkts[i].version_major = 3;
    pkts[i].version_minor = 3;
    pkts[i].payload_len = 4;
    pkts[i].length = 4;
    pkts[i].payload[0] = 1;
  }
  return pkts;
}
