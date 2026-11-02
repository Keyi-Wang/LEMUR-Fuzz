#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "llm/dns/dns.h"
#include "llm/ssh/ssh.h"
#include "llm/tls/tls.h"
#include "llm/dicom/dicom.h"

/* No fixer is invoked: the invariant is R(P(M)) == M, not normalization. */
#define MAX_PACKETS 16
#define BRIDGE(proto) \
int roundtrip_##proto(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *cap, int structural, uint32_t *count) { \
    proto##_packet_t *p = calloc(MAX_PACKETS, sizeof(*p)); \
    if (!p) return -10; \
    size_t n = parse_##proto##_msg(in, len, p, MAX_PACKETS); \
    *count = n; \
    if (!n) { free(p); return -11; } \
    prepare_##proto(p, n, structural); \
    int rc = reassemble_##proto##_msgs(p, n, out, cap); \
    free(p); return rc; \
}
static void prepare_dns(dns_packet_t *p,size_t n,int structural) {
    if (structural) for(size_t i=0;i<n;i++) { p[i].u.dns_message.wire_len=0; }
}
static void prepare_ssh(ssh_packet_t *p,size_t n,int structural) {
    if (structural) for(size_t i=0;i<n;i++) { p[i].wire=NULL; p[i].wire_len=0; }
}
static void prepare_tls(tls_packet_t *p,size_t n,int structural) {
    if (structural) for(size_t i=0;i<n;i++) { p[i].wire=NULL; p[i].wire_len=0; }
}
static void prepare_dicom(dicom_packet_t *p,size_t n,int structural) {
    if (structural) for(size_t i=0;i<n;i++) p[i].raw_length=0;
}
BRIDGE(dns)
BRIDGE(ssh)
BRIDGE(tls)
BRIDGE(dicom)

/* Capability probes are separate from round-trip tests. Preserved opaque bytes
 * are useful but are not evidence of a field-level parser. */
enum { GAP_UNCLASSIFIED=1, GAP_OPAQUE_FIELDS=2, GAP_CAPACITY=4,
       GAP_FRAGMENT=8, GAP_MULTIPLE_HANDSHAKES=16 };
unsigned gaps_dns(const uint8_t *in, uint32_t len) {
    dns_packet_t *p=calloc(MAX_PACKETS,sizeof(*p)); if(!p)return GAP_CAPACITY;
    size_t n=parse_dns_msg(in,len,p,MAX_PACKETS); unsigned gaps=n?0:GAP_UNCLASSIFIED;
    for(size_t i=0;i<n;i++) {
        dns_message_t *m=&p[i].u.dns_message;
        if (m->capacity_exceeded) gaps|=GAP_CAPACITY;
        if(m->header.opcode==6 && m->dso_tlv_count==0 && len>12) gaps|=GAP_UNCLASSIFIED; /* DSO, RFC8490 */
        if(m->header.opcode!=6 && (m->header.qdcount!=m->question_count || m->header.ancount!=m->answer_count ||
           m->header.nscount!=m->authority_count || m->header.arcount!=m->additional_count+m->has_opt)) gaps|=GAP_CAPACITY;
        if(m->header.opcode==6 && (m->header.qdcount || m->header.ancount || m->header.nscount || m->header.arcount)) gaps|=GAP_CAPACITY;
        if(m->header.opcode==6) for(unsigned k=0;k<m->dso_tlv_count;k++) {
            if(m->dso_tlvs[k].tlv_length>m->dso_tlvs[k].data_len) gaps|=GAP_CAPACITY;
            if(m->dso_tlvs[k].tlv_type==1 && m->dso_tlvs[k].tlv_length==8 && !m->dso_tlvs[k].has_keepalive) gaps|=GAP_OPAQUE_FIELDS;
        }
        dns_resource_record_t *sections[]={m->answers,m->authorities,m->additionals};
        unsigned counts[]={m->answer_count,m->authority_count,m->additional_count};
        for(unsigned s=0;s<3;s++) for(unsigned k=0;k<counts[s];k++) {
            dns_resource_record_t *rr=&sections[s][k];
            if(rr->rdlength>rr->rdata_len)gaps|=GAP_CAPACITY;
            if(rr->rdlength && rr->type!=10 && !rr->rdata_schema)gaps|=GAP_OPAQUE_FIELDS;
        }
        if(m->has_opt && m->opt_rr.rdata_len && !m->opt_rr.option_count)gaps|=GAP_OPAQUE_FIELDS;
    }
    free(p);return gaps;
}
unsigned gaps_ssh(const uint8_t *in, uint32_t len) {
    ssh_packet_t *p=calloc(MAX_PACKETS,sizeof(*p)); if(!p)return GAP_CAPACITY;
    size_t n=parse_ssh_msg(in,len,p,MAX_PACKETS); unsigned gaps=n?0:GAP_UNCLASSIFIED;
    for(size_t i=0;i<n;i++) {
        if(p[i].type==SSH_TRANSPORT_PACKET || p[i].type==SSH_OPAQUE) gaps|=GAP_UNCLASSIFIED;
        if(p[i].type>=SSH_DISCONNECT) {
            if(!p[i].u.typed.field_schema)gaps|=GAP_CAPACITY;
            if(p[i].u.typed.trailing_payload.len)gaps|=GAP_OPAQUE_FIELDS;
        }
    }
    free(p);return gaps;
}
unsigned gaps_tls(const uint8_t *in, uint32_t len) {
    tls_packet_t *p=calloc(MAX_PACKETS,sizeof(*p)); if(!p)return GAP_CAPACITY;
    size_t n=parse_tls_msg(in,len,p,MAX_PACKETS); unsigned gaps=n?0:GAP_UNCLASSIFIED;
    for(size_t i=0;i<n;i++) if(p[i].type==TLS_PACKET_UNKNOWN) gaps|=GAP_OPAQUE_FIELDS;
    for(size_t i=0;i<n;i++) if(p[i].type==TLS_PACKET_HANDSHAKE) {
        tls_handshake_packet_t *h=&p[i].u.handshake;
        if(h->is_fragment && !h->fragment_decoded)gaps|=GAP_FRAGMENT;
        if(h->following_handshakes_len && !h->following_handshake_count && !h->fragment_decoded)gaps|=GAP_MULTIPLE_HANDSHAKES;
        if(!h->body_schema && !h->fragmented_body_schema)gaps|=GAP_OPAQUE_FIELDS;
        else if(h->has_client_hello && h->client_hello.extensions_len && !h->client_hello.extension_count)gaps|=GAP_OPAQUE_FIELDS;
    }
    free(p);return gaps;
}
unsigned gaps_dicom(const uint8_t *in, uint32_t len) {
    dicom_packet_t *p=calloc(MAX_PACKETS,sizeof(*p)); if(!p)return GAP_CAPACITY;
    size_t n=parse_dicom_msg(in,len,p,MAX_PACKETS); unsigned gaps=n?0:GAP_UNCLASSIFIED;
    for(size_t i=0;i<n;i++) {
        if(p[i].type==DICOM_PKT_UNKNOWN)gaps|=GAP_UNCLASSIFIED;
        if(p[i].type==DICOM_PKT_A_ASSOCIATE_RQ && p[i].u.a_associate_rq.user_info.has_user_data)gaps|=GAP_OPAQUE_FIELDS;
        if(p[i].type==DICOM_PKT_P_DATA_TF) {
            if (p[i].u.p_data_tf.pdv_tail_length) gaps|=GAP_CAPACITY;
            for(unsigned k=0;k<p[i].u.p_data_tf.pdv_count;k++) {
                dicom_pdv_item_t *d=&p[i].u.p_data_tf.pdvs[k];
                if (d->data_tail_length) gaps|=GAP_CAPACITY;
                if((d->control_header&1) && (d->control_header&2) && !d->has_dimse_command_fields)gaps|=GAP_FRAGMENT;
                /* Dataset PDVs are application dataset payload, not DIMSE command-message fields. */
            }
        }
    }
    free(p);return gaps;
}
