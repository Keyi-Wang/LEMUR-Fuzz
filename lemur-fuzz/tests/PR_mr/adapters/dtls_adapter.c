// tests/mr/adapters/dtls_adapter.c
#include "dut.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>


#include "../../../llm/dtls/dtls_packets.h"  


extern size_t parse_dtls_msg(const uint8_t *buf, size_t buf_len,
                            dtls_packet_t *out_packets, size_t max_count);
extern int reassemble_dtls_msgs(const dtls_packet_t *packets, uint32_t num_packets,
                               uint8_t *output_buf, uint32_t *out_len);


#ifndef dtls_MAX_MSGS_INIT
#define dtls_MAX_MSGS_INIT 128       
#endif
#ifndef dtls_MAX_MSGS_CAP
#define dtls_MAX_MSGS_CAP  8192      
#endif
#ifndef dtls_REASM_INIT_CAP
#define dtls_REASM_INIT_CAP (4*1024*1024)  
#endif
#ifndef dtls_REASM_MAX_CAP
#define dtls_REASM_MAX_CAP  (64*1024*1024) 
#endif

typedef struct {
  dtls_packet_t *pkts;
  size_t        n;         
  size_t        cap;       
  size_t        orig_len;  
} dtls_holder_t;


static void free_holder(dtls_holder_t *h) {
  if (!h) return;
  free(h->pkts);
  free(h);
}



int dut_parse(const uint8_t *buf, size_t len, msg_array_t *out) {
  if (!out) return -1;

  dtls_holder_t *holder = (dtls_holder_t*)calloc(1, sizeof(*holder));
  if (!holder) return -ENOMEM;
  holder->orig_len = len;

  size_t cap = dtls_MAX_MSGS_INIT;
  holder->pkts = (dtls_packet_t*)malloc(cap * sizeof(dtls_packet_t));
  if (!holder->pkts) { free(holder); return -ENOMEM; }

  for (;;) {
    size_t n = parse_dtls_msg(buf, len, holder->pkts, cap);
    holder->n = n;
    holder->cap = cap;

    if (n < cap) break;           
    if (cap >= dtls_MAX_MSGS_CAP) 
      break;

    cap = cap * 2;
    if (cap > dtls_MAX_MSGS_CAP) cap = dtls_MAX_MSGS_CAP;
    dtls_packet_t *np = (dtls_packet_t*)realloc(holder->pkts, cap * sizeof(dtls_packet_t));
    memset(np,0,sizeof(dtls_packet_t)*cap);
    if (!np) { free_holder(holder); return -ENOMEM; }
    holder->pkts = np;
  }

  out->v = (msg_t*)calloc(1, sizeof(msg_t));
  if (!out->v) { free_holder(holder); return -ENOMEM; }
  out->n = holder->n;               
  out->v[0].data = (uint8_t*)holder;
  out->v[0].len  = 0;              

  return 0;
}

int dut_reassemble(const msg_array_t *in, uint8_t **out_buf, size_t *out_len) {
  if (!in || !out_buf || !out_len) return -1;
  if (!in->v || in->n == 0) {      
    *out_buf = (uint8_t*)malloc(1);
    if (!*out_buf) return -ENOMEM;
    *out_len = 0;
    return 0;
  }

  dtls_holder_t *holder = (dtls_holder_t*)in->v[0].data;
  if (!holder) return -1;

#ifdef dtls_REASM_SUPPORTS_QUERY_LEN
  
  uint32_t need = 0;
  if (reassemble_dtls_msgs(holder->pkts, (uint32_t)holder->n, NULL, &need) != 0 || need == 0) {
  } else {
    uint8_t *buf = (uint8_t*)malloc(need);
    if (!buf) return -ENOMEM;
    uint32_t outn = 0;
    int rc = reassemble_dtls_msgs(holder->pkts, (uint32_t)holder->n, buf, &outn);
    if (rc != 0) { free(buf); return rc; }
    *out_buf = buf; *out_len = (size_t)outn; return 0;
  }
#endif

  size_t cap = holder->orig_len ? (holder->orig_len * 2 + holder->n * 8 + 1024)
                                : dtls_REASM_INIT_CAP;
  if (cap > dtls_REASM_MAX_CAP) cap = dtls_REASM_MAX_CAP;
  if (cap < 1024) cap = 1024;

  for (int attempt = 0; attempt < 6; ++attempt) {
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) return -ENOMEM;

    uint32_t outn = 0;
    int rc = reassemble_dtls_msgs(holder->pkts, (uint32_t)holder->n, buf, &outn);
    if (rc == 0) {
      *out_buf = buf;
      *out_len = (size_t)outn;
      return 0;
    }

    free(buf);
    if (outn > cap && outn <= dtls_REASM_MAX_CAP) {
      cap = outn;                
    } else {
      cap = cap << 1;            
    }
    if (cap > dtls_REASM_MAX_CAP) break;
  }
  return -ENOMEM;  
}

void dut_free_msg_array(msg_array_t *arr) {
  if (!arr || !arr->v) return;
  dtls_holder_t *holder = (dtls_holder_t*)arr->v[0].data;
  free_holder(holder);
  free(arr->v);
  arr->v = NULL; arr->n = 0;
}

void dut_free_buffer(uint8_t *buf) {
  free(buf);
}
