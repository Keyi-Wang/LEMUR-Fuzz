#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dns_packets.h"

static uint32_t prng_u32(uint32_t *s){*s = (*s)*1664525u + 1013904223u; return *s;}
static uint16_t clamp16(int v){ if(v<0) return 0; if(v>0xFFFF) return 0xFFFF; return (uint16_t)v; }
static uint32_t clamp32_long(long long v){ if(v<0) return 0; if(v>0xFFFFFFFFu) return 0xFFFFFFFFu; return (uint32_t)v; }
static uint16_t bswap16(uint16_t x){return (uint16_t)((x>>8)|((x&0xFFu)<<8));}
static uint32_t bswap32(uint32_t x){return ((x>>24)&0xFFu)|(((x>>16)&0xFFu)<<8)|(((x>>8)&0xFFu)<<16)|((x&0xFFu)<<24);} 

static const uint16_t dns_query_type_pool[] = {
    1,    /* A */
    2,    /* NS */
    5,    /* CNAME */
    6,    /* SOA */
    10,   /* NULL */
    12,   /* PTR */
    13,   /* HINFO */
    15,   /* MX */
    16,   /* TXT */
    28,   /* AAAA */
    29,   /* LOC: present in the ProfuzzBench dnsmasq seed */
    33,   /* SRV */
    39,   /* DNAME */
    43,   /* DS */
    44,   /* SSHFP */
    45,   /* IPSECKEY */
    46,   /* RRSIG */
    47,   /* NSEC */
    48,   /* DNSKEY */
    50,   /* NSEC3 */
    51,   /* NSEC3PARAM */
    52,   /* TLSA */
    55,   /* HIP */
    59,   /* CDS */
    60,   /* CDNSKEY */
    61,   /* OPENPGPKEY */
    63,   /* ZONEMD */
    64,   /* SVCB */
    65,   /* HTTPS */
    99,   /* SPF */
    108,  /* EUI48 */
    109,  /* EUI64 */
    249,  /* TKEY */
    250,  /* TSIG */
    251,  /* IXFR */
    252,  /* AXFR */
    255,  /* ANY */
    257,  /* CAA */
    32769 /* DLV */
};

static const uint16_t dns_query_class_pool[] = {
    1,     /* IN */
    3,     /* CH, for version.bind-style control queries */
    4,     /* HS */
    254,   /* NONE, used by UPDATE prerequisites */
    255,   /* ANY */
    65280  /* private-use boundary */
};


typedef struct dns_query_template_s {
    const char *name;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t rd;
    uint8_t edns;
    uint16_t edns_payload;
    uint16_t edns_flags;
} dns_query_template_t;

static const dns_query_template_t dns_query_templates[] = {
    /* ProfuzzBench dnsmasq seed coverage: preserve every observed message kind. */
    {"google.com", 16, 1, 1, 0, 0, 0},                         /* TXT */
    {"google.com", 15, 1, 1, 0, 0, 0},                         /* MX */
    {"google.com", 29, 1, 1, 0, 0, 0},                         /* LOC */
    {"104.9.192.66.in-addr.arpa", 12, 1, 1, 0, 0, 0},          /* PTR */
    {"www.netbsd.org", 1, 1, 1, 0, 0, 0},                      /* A */
    {"www.netbsd.org", 28, 1, 1, 0, 0, 0},                     /* AAAA */
    {"www.isc.org", 255, 1, 1, 0, 0, 0},                       /* ANY */
    {"isc.org", 2, 1, 1, 0, 0, 0},                             /* NS */
    {"_ldap._tcp.dc._msdcs.utelsystems.local", 33, 1, 1, 0, 0, 0}, /* SRV */

    /* dnsmasq server-control and cache paths. */
    {"version.bind", 16, 3, 0, 0, 0, 0},                       /* CH TXT version.bind */
    {"hostname.bind", 16, 3, 0, 0, 0, 0},
    {"authors.bind", 16, 3, 0, 0, 0, 0},
    {"localhost", 1, 1, 1, 0, 0, 0},
    {"localhost", 28, 1, 1, 0, 0, 0},
    {"1.0.0.127.in-addr.arpa", 12, 1, 1, 0, 0, 0},
    {"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", 12, 1, 1, 0, 0, 0},

    /* Common RR families and modern query types. */
    {"example.com", 6, 1, 1, 0, 0, 0},                         /* SOA */
    {"www.example.com", 5, 1, 1, 0, 0, 0},                     /* CNAME */
    {"example.com", 257, 1, 1, 0, 0, 0},                       /* CAA */
    {"_dns.example.com", 64, 1, 1, 1, 1232, 0},                /* SVCB + EDNS */
    {"example.com", 65, 1, 1, 1, 1232, 0},                     /* HTTPS + EDNS */
    {"_443._tcp.example.com", 52, 1, 1, 1, 1232, 0},           /* TLSA */
    {"example.com", 99, 1, 1, 0, 0, 0},                        /* SPF */
    {"example.com", 10, 1, 1, 0, 0, 0},                        /* NULL */
    {"example.com", 13, 1, 1, 0, 0, 0},                        /* HINFO */

    /* DNSSEC/EDNS paths: legal plain UDP queries with no secret material. */
    {"example.com", 43, 1, 1, 1, 1232, 0x8000},                /* DS + DO */
    {"example.com", 48, 1, 1, 1, 1232, 0x8000},                /* DNSKEY + DO */
    {"example.com", 46, 1, 1, 1, 1232, 0x8000},                /* RRSIG + DO */
    {"example.com", 47, 1, 1, 1, 1232, 0x8000},                /* NSEC + DO */
    {"example.com", 50, 1, 1, 1, 1232, 0x8000},                /* NSEC3 + DO */
    {"example.com", 32769, 1, 1, 1, 4096, 0},                 /* DLV historical parser branch */

    /* Boundary but still valid domain names. */
    {".", 1, 1, 1, 0, 0, 0},
    {"a.example.com", 1, 1, 1, 0, 0, 0},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", 16, 1, 1, 1, 1232, 0},
    {"xn--bcher-kva.example", 1, 1, 1, 0, 0, 0},
    {"*.example.com", 255, 1, 1, 0, 0, 0},
    {"test.local", 255, 255, 1, 0, 0, 0},

    /* ProfuzzBench tutorial dnsmasq.conf/runbook local-answer examples. */
    {"test.com", 1, 1, 1, 0, 0, 0},
    {"test.com", 28, 1, 1, 0, 0, 0},
    {"test.com", 255, 1, 1, 0, 0, 0},
    {"maildomain.com", 15, 1, 1, 0, 0, 0},
    {"servermachine.com", 1, 1, 1, 0, 0, 0},
    {"_ldap._tcp.example.com", 33, 1, 1, 0, 0, 0},
    {"_http._tcp.example.com", 16, 1, 1, 0, 0, 0},
    {"_http._tcp.dns-sd-services", 12, 1, 1, 0, 0, 0},
    {"bertand", 5, 1, 1, 0, 0, 0},
    {"thekelleys.org.uk", 1, 1, 1, 0, 0, 0},
    {"double-click.net", 1, 1, 1, 0, 0, 0},
    {"3.168.192.in-addr.arpa", 12, 1, 1, 0, 0, 0},

    /* Additional RFC-defined request families and service-discovery names. */
    {"_443._tcp.example.com", 52, 1, 1, 1, 1232, 0x8000},          /* TLSA with DO */
    {"_853._tcp.example.com", 52, 1, 1, 1, 1232, 0x8000},
    {"_sip._udp.example.com", 33, 1, 1, 0, 0, 0},                 /* SRV */
    {"_xmpp-server._tcp.example.com", 33, 1, 1, 0, 0, 0},
    {"_dns.resolver.arpa", 64, 1, 1, 1, 1232, 0},                /* SVCB */
    {"dns.google", 65, 1, 1, 1, 1232, 0},                        /* HTTPS */
    {"_services._dns-sd._udp.local", 12, 1, 1, 0, 0, 0},
    {"_dns-sd._udp.local", 12, 1, 1, 0, 0, 0},
    {"id.server", 16, 3, 0, 0, 0, 0},                             /* CH TXT */
    {"bind", 16, 3, 0, 0, 0, 0},
    {"example.com", 39, 1, 1, 0, 0, 0},                           /* DNAME */
    {"example.com", 44, 1, 1, 1, 1232, 0x8000},                  /* SSHFP */
    {"example.com", 45, 1, 1, 1, 1232, 0x8000},                  /* IPSECKEY */
    {"example.com", 51, 1, 1, 1, 1232, 0x8000},                  /* NSEC3PARAM */
    {"example.com", 59, 1, 1, 1, 1232, 0x8000},                  /* CDS */
    {"example.com", 60, 1, 1, 1, 1232, 0x8000},                  /* CDNSKEY */
    {"example.com", 61, 1, 1, 1, 1232, 0x8000},                  /* OPENPGPKEY */
    {"example.com", 63, 1, 1, 1, 1232, 0x8000},                  /* ZONEMD */
    {"example.com", 108, 1, 1, 0, 0, 0},                         /* EUI48 */
    {"example.com", 109, 1, 1, 0, 0, 0},                         /* EUI64 */
    {"example.com", 249, 1, 1, 1, 1232, 0},                      /* TKEY */
    {"example.com", 250, 255, 1, 1, 1232, 0},                    /* TSIG/ANY */
    {"example.com", 251, 1, 1, 1, 1232, 0},                      /* IXFR */
    {"example.com", 252, 1, 1, 1, 1232, 0},                      /* AXFR */
    {"hostmaster.example.com", 6, 1, 1, 0, 0, 0}
};

static const char *const dns_query_name_pool[] = {
    "google.com",
    "www.netbsd.org",
    "www.isc.org",
    "isc.org",
    "104.9.192.66.in-addr.arpa",
    "1.0.0.127.in-addr.arpa",
    "_ldap._tcp.dc._msdcs.utelsystems.local",
    "_ssh._tcp.example.com",
    "version.bind",
    "localhost",
    "example.com",
    "example.org",
    "test.local",
    "test.com",
    "maildomain.com",
    "servermachine.com",
    "_ldap._tcp.example.com",
    "_http._tcp.example.com",
    "thekelleys.org.uk",
    "double-click.net",
    "_443._tcp.example.com",
    "_853._tcp.example.com",
    "_sip._udp.example.com",
    "_xmpp-server._tcp.example.com",
    "_services._dns-sd._udp.local",
    "_dns-sd._udp.local",
    "_dns.resolver.arpa",
    "dns.google",
    "id.server",
    "bind",
    "hostmaster.example.com",
    "."
};

static void dns_clear_response_sections(dns_message_t *m)
{
    if (!m) return;
    m->answer_count = 0;
    m->authority_count = 0;
    memset(m->answers, 0, sizeof(m->answers));
    memset(m->authorities, 0, sizeof(m->authorities));
}

static size_t pick_msgs(dns_packet_t *pkts, size_t n, size_t *idxs, size_t max){
    size_t c=0; for(size_t i=0;i<n && c<max;i++){ if(pkts[i].type==DNS_MESSAGE){ idxs[c++]=i; } } return c;
}

// Field list for DNS_MESSAGE packet (dns_message_t):
// - header (dns_header_t)
// - questions[] and question_count
// - answers[] and answer_count
// - authorities[] and authority_count
// - additionals[] and additional_count
// - opt_rr and has_opt
// - wire and wire_len (preserved wire bytes)

// header: mutable (contains many fields)
void mutate_header(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xABCDEF01u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){
        dns_message_t *m=&pkts[i].u.dns_message;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: m->header.id ^= (uint16_t)(r); break; // boundaries/equivalence
            case 1: m->header.qr = (m->header.qr?0:1); break; // canonical flip
            case 2: m->header.opcode = (uint8_t)((m->header.opcode+1)&0xF); break; // allowed enum
            case 3: m->header.rcode = (uint8_t)((m->header.rcode+1)&0xF); break;
            case 4: m->header.rd ^= 1; m->header.ra ^= (r>>1)&1; break;
            case 5: m->header.tc ^= 1; m->header.aa ^= 1; break;
            case 6: m->header.z = (uint8_t)(r & 0x7); break; // z must be 0 but fuzz variants
            case 7:
                m->header.qdcount = clamp16((int)m->question_count + (int)(r%3) - 1);
                m->header.ancount = clamp16((int)m->answer_count + (int)((r>>2)%3) - 1);
                m->header.nscount = clamp16((int)m->authority_count + (int)((r>>4)%3) - 1);
                m->header.arcount = clamp16((int)m->additional_count + (int)((r>>6)%3) - 1);
                break;
        }
    }
}

// questions: optional, repeatable
void add_questions(dns_packet_t *pkts, size_t n){
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){
        dns_message_t *m=&pkts[i].u.dns_message;
        if(m->question_count < DNS_MAX_QUESTIONS){
            dns_question_t *q=&m->questions[m->question_count++];
            memset(q,0,sizeof(*q));
            q->packet_type=DNS_QUESTION; q->present=1; q->name_len=1; q->name[0]=0; q->qtype=1; q->qclass=1;
        }
    }
}
void delete_questions(dns_packet_t *pkts, size_t n){
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){
        dns_message_t *m=&pkts[i].u.dns_message;
        if(m->question_count>0){ m->question_count--; }
    }
}
void repeat_questions(dns_packet_t *pkts, size_t n){
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){
        dns_message_t *m=&pkts[i].u.dns_message;
        if(m->question_count==0) continue;
        if(m->question_count < DNS_MAX_QUESTIONS){ m->questions[m->question_count] = m->questions[m->question_count-1]; m->question_count++; }
    }
}
static void dns_set_name(dns_question_t *q, const char *label);
static void dns_ensure_one_question(dns_message_t *m);

static void mutate_qname_bytes(dns_question_t *q, uint32_t *seed){
    if(!q || !seed) return;
    if(q->name_len==0){ q->name_len=1; q->name[0]=0; }
    uint32_t r = prng_u32(seed);
    switch (r % 10) {
        case 0: dns_set_name(q, dns_query_name_pool[prng_u32(seed) % (sizeof(dns_query_name_pool)/sizeof(dns_query_name_pool[0]))]); break;
        case 1: dns_set_name(q, "google.com"); break;
        case 2: dns_set_name(q, "www.netbsd.org"); break;
        case 3: dns_set_name(q, "www.isc.org"); break;
        case 4: dns_set_name(q, "104.9.192.66.in-addr.arpa"); break;
        case 5: dns_set_name(q, "_ldap._tcp.dc._msdcs.utelsystems.local"); break;
        case 6: { /* DNS names are case-insensitive; this explores parser paths while staying valid. */
            uint16_t lim=q->name_len; if(lim>DNS_MAX_NAME_LEN) lim=DNS_MAX_NAME_LEN;
            for(uint16_t i=1;i<lim;i++) { uint8_t c=q->name[i]; if(c>='a'&&c<='z'&&(prng_u32(seed)&1)) q->name[i]=(uint8_t)(c-32); }
            break;
        }
        case 7: { /* Change one label character without corrupting length octets. */
            uint16_t off=0;
            while(off < q->name_len && q->name[off] && (q->name[off] & 0xc0) == 0) {
                uint8_t l=q->name[off++];
                if(l && off + l <= q->name_len) {
                    uint16_t pos = (uint16_t)(off + (prng_u32(seed) % l));
                    q->name[pos] = (uint8_t)('a' + (prng_u32(seed) % 26));
                    break;
                }
                off = (uint16_t)(off + l);
            }
            break;
        }
        case 8: dns_set_name(q, "."); break;
        default: dns_set_name(q, "localhost"); break;
    }
}

void mutate_questions(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x10203040u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){
        dns_message_t *m=&pkts[i].u.dns_message;
        if (m->question_count == 0) dns_ensure_one_question(m);
        if (m->header.opcode == 0 && m->question_count > 1) m->question_count = 1;
        for(uint16_t j=0;j<m->question_count && j<DNS_MAX_QUESTIONS;j++){
            dns_question_t *q=&m->questions[j];
            q->packet_type = DNS_QUESTION;
            q->present = 1;
            uint32_t r=prng_u32(&seed);
            switch(r%18){
                case 0: mutate_qname_bytes(q,&seed); break;
                case 1: q->qtype = dns_query_type_pool[prng_u32(&seed) % (sizeof(dns_query_type_pool)/sizeof(dns_query_type_pool[0]))]; break;
                case 2: q->qclass = dns_query_class_pool[prng_u32(&seed) % (sizeof(dns_query_class_pool)/sizeof(dns_query_class_pool[0]))]; break;
                case 3: q->qtype = 29; dns_set_name(q, "google.com"); break; /* LOC, in ProfuzzBench seed */
                case 4: q->qtype = 12; dns_set_name(q, "104.9.192.66.in-addr.arpa"); q->qclass = 1; break;
                case 5: q->qtype = 33; dns_set_name(q, "_ldap._tcp.dc._msdcs.utelsystems.local"); q->qclass = 1; break;
                case 6: q->qtype = 16; dns_set_name(q, "version.bind"); q->qclass = 3; break;
                case 7: q->qtype = 255; dns_set_name(q, "www.isc.org"); q->qclass = 1; break;
                case 8: q->qtype = 2; dns_set_name(q, "isc.org"); q->qclass = 1; break;
                case 9: q->qtype = 1; dns_set_name(q, "www.netbsd.org"); q->qclass = 1; break;
                case 10: q->qtype = 28; dns_set_name(q, "www.netbsd.org"); q->qclass = 1; break;
                case 11: q->qtype = 1; dns_set_name(q, "test.com"); q->qclass = 1; break;
                case 12: q->qtype = 255; dns_set_name(q, "test.com"); q->qclass = 1; break;
                case 13: q->qtype = 15; dns_set_name(q, "maildomain.com"); q->qclass = 1; break;
                case 14: q->qtype = 33; dns_set_name(q, "_ldap._tcp.example.com"); q->qclass = 1; break;
                case 15: q->qtype = 16; dns_set_name(q, "_http._tcp.example.com"); q->qclass = 1; break;
                case 16: q->qtype = 1; dns_set_name(q, "thekelleys.org.uk"); q->qclass = 1; break;
                default: q->qtype = 15; dns_set_name(q, "google.com"); q->qclass = 1; break;
            }
        }
        if (m->header.opcode == 0) {
            m->header.qr = 0;
            m->header.rd = 1;
            m->header.ra = 0;
            m->header.aa = 0;
            m->header.tc = 0;
            m->header.rcode = 0;
            m->header.z = 0;
            dns_clear_response_sections(m);
        }
    }
}

// answers: optional, repeatable
void add_answers(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->answer_count<DNS_MAX_RRS){ dns_resource_record_t *rr=&m->answers[m->answer_count++]; memset(rr,0,sizeof(*rr)); rr->packet_type=DNS_RESOURCE_RECORD; rr->present=1; rr->name_len=1; rr->name[0]=0; rr->type=1; rr->class_code=1; rr->ttl=0; rr->rdlength=0; rr->rdata_len=0; } }}
void delete_answers(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->answer_count>0){ m->answer_count--; } }}
void repeat_answers(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->answer_count==0) continue; if(m->answer_count<DNS_MAX_RRS){ m->answers[m->answer_count]=m->answers[m->answer_count-1]; m->answer_count++; } }}

static void dns_sync_tsig_rdata(dns_resource_record_t *rr)
{
    if (!rr || !rr->has_tsig) return;
    uint32_t off = 0;
    uint16_t alg_len = rr->tsig_algorithm_name_len;
    if (alg_len > DNS_MAX_NAME_LEN) alg_len = DNS_MAX_NAME_LEN;
    if (off + alg_len > DNS_MAX_RDATA) return;
    if (alg_len) memcpy(rr->rdata + off, rr->tsig_algorithm_name, alg_len);
    off += alg_len;
    if (off + 10 > DNS_MAX_RDATA) return;
    rr->rdata[off++] = (uint8_t)(rr->tsig_time_signed >> 40);
    rr->rdata[off++] = (uint8_t)(rr->tsig_time_signed >> 32);
    rr->rdata[off++] = (uint8_t)(rr->tsig_time_signed >> 24);
    rr->rdata[off++] = (uint8_t)(rr->tsig_time_signed >> 16);
    rr->rdata[off++] = (uint8_t)(rr->tsig_time_signed >> 8);
    rr->rdata[off++] = (uint8_t)rr->tsig_time_signed;
    rr->rdata[off++] = (uint8_t)(rr->tsig_fudge >> 8);
    rr->rdata[off++] = (uint8_t)rr->tsig_fudge;
    uint16_t mac_len = rr->tsig_mac_len;
    if (mac_len > DNS_MAX_TSIG_MAC) mac_len = DNS_MAX_TSIG_MAC;
    if (off + 2u + mac_len + 6u > DNS_MAX_RDATA) return;
    rr->rdata[off++] = (uint8_t)(mac_len >> 8);
    rr->rdata[off++] = (uint8_t)mac_len;
    if (mac_len) memcpy(rr->rdata + off, rr->tsig_mac, mac_len);
    off += mac_len;
    rr->rdata[off++] = (uint8_t)(rr->tsig_original_id >> 8);
    rr->rdata[off++] = (uint8_t)rr->tsig_original_id;
    rr->rdata[off++] = (uint8_t)(rr->tsig_error >> 8);
    rr->rdata[off++] = (uint8_t)rr->tsig_error;
    uint16_t other_len = rr->tsig_other_len;
    if (other_len > DNS_MAX_TSIG_OTHER) other_len = DNS_MAX_TSIG_OTHER;
    if (off + 2u + other_len > DNS_MAX_RDATA) return;
    rr->rdata[off++] = (uint8_t)(other_len >> 8);
    rr->rdata[off++] = (uint8_t)other_len;
    if (other_len) memcpy(rr->rdata + off, rr->tsig_other_data, other_len);
    off += other_len;
    rr->type = 250;
    rr->rdata_schema = 250;
    rr->rdlength = (uint16_t)off;
    rr->rdata_len = (uint16_t)off;
}

static void mutate_tsig_fields(dns_resource_record_t *rr, uint32_t *seed)
{
    if (!rr || !rr->has_tsig || !seed) return;
    switch (prng_u32(seed) % 8) {
        case 0: rr->tsig_time_signed ^= ((uint64_t)(prng_u32(seed) & 0xffffu) << 8); break;
        case 1: rr->tsig_fudge ^= (uint16_t)prng_u32(seed); break;
        case 2: rr->tsig_original_id ^= (uint16_t)prng_u32(seed); break;
        case 3: rr->tsig_error = (uint16_t)(prng_u32(seed) % 24u); break;
        case 4: if (rr->tsig_mac_len < DNS_MAX_TSIG_MAC) rr->tsig_mac[rr->tsig_mac_len++] = (uint8_t)prng_u32(seed); break;
        case 5: if (rr->tsig_mac_len) rr->tsig_mac[prng_u32(seed) % rr->tsig_mac_len] ^= (uint8_t)prng_u32(seed); break;
        case 6: if (rr->tsig_other_len < DNS_MAX_TSIG_OTHER) rr->tsig_other_data[rr->tsig_other_len++] = (uint8_t)prng_u32(seed); break;
        default: if (rr->tsig_algorithm_name_len > 1) rr->tsig_algorithm_name[1] ^= (uint8_t)(prng_u32(seed) & 0x3f); break;
    }
    dns_sync_tsig_rdata(rr);
}

static void mutate_rr(dns_resource_record_t *rr, uint32_t *seed){
    if(rr->name_len==0){ rr->name_len=1; rr->name[0]=0; }
    for(uint16_t i=0;i<rr->name_len;i++){ if((prng_u32(seed)&3)==0) rr->name[i]^=(uint8_t)prng_u32(seed); }
    switch(prng_u32(seed)%8){
        case 0: rr->type ^= (uint16_t)prng_u32(seed); break;
        case 1: rr->class_code ^= (uint16_t)(prng_u32(seed)>>1); break;
        case 2: rr->ttl = bswap32(rr->ttl) ^ prng_u32(seed); break;
        case 3: if(rr->rdata_len < DNS_MAX_RDATA){ rr->rdata[rr->rdata_len++] = (uint8_t)prng_u32(seed); rr->rdlength = rr->rdata_len; } break;
        case 4: if(rr->rdata_len>0){ rr->rdata_len--; rr->rdlength=rr->rdata_len; } break;
        case 5: rr->present ^=1; break;
        case 6: rr->rdlength ^= (uint16_t)prng_u32(seed); rr->rdata_len = rr->rdlength % (DNS_MAX_RDATA+1); break;
        case 7: if(rr->name_len+1<=DNS_MAX_NAME_LEN){ rr->name[rr->name_len++]=0; } break;
    }
    if (rr->rdata_schema) {
        if (rr->has_tsig || rr->rdata_schema == 250) { mutate_tsig_fields(rr, seed); }
        else switch (prng_u32(seed) % 6) {
            case 0: if (rr->address_len) rr->address[prng_u32(seed) % rr->address_len] ^= (uint8_t)prng_u32(seed); break;
            case 1: if (rr->u16_count) rr->u16_values[prng_u32(seed) % rr->u16_count] ^= (uint16_t)prng_u32(seed); break;
            case 2: if (rr->u32_count) rr->u32_values[prng_u32(seed) % rr->u32_count] ^= prng_u32(seed); break;
            case 3: if (rr->name_count) rr->names[prng_u32(seed) % rr->name_count].wire[0] ^= (uint8_t)(prng_u32(seed) & 0x3f); break;
            case 4: if (rr->string_count) { uint8_t si = prng_u32(seed) % rr->string_count; if (rr->strings[si].len) rr->strings[si].data[0] ^= (uint8_t)prng_u32(seed); } break;
            default: rr->rdata_schema = rr->type; break;
        }
    }
}
void mutate_answers(dns_packet_t *pkts, size_t n){ uint32_t seed=0xA5A5A5A5u; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; for(uint16_t j=0;j<m->answer_count;j++) mutate_rr(&m->answers[j], &seed); }}

// authorities: optional, repeatable
void add_authorities(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->authority_count<DNS_MAX_RRS){ dns_resource_record_t *rr=&m->authorities[m->authority_count++]; memset(rr,0,sizeof(*rr)); rr->packet_type=DNS_RESOURCE_RECORD; rr->present=1; rr->name_len=1; rr->name[0]=0; rr->type=2; rr->class_code=1; rr->ttl=0; rr->rdlength=0; rr->rdata_len=0; } }}
void delete_authorities(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->authority_count>0){ m->authority_count--; } }}
void repeat_authorities(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->authority_count==0) continue; if(m->authority_count<DNS_MAX_RRS){ m->authorities[m->authority_count]=m->authorities[m->authority_count-1]; m->authority_count++; } }}
void mutate_authorities(dns_packet_t *pkts, size_t n){ uint32_t seed=0x5AA55AA5u; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; for(uint16_t j=0;j<m->authority_count;j++) mutate_rr(&m->authorities[j], &seed); }}

// additionals: optional, repeatable
void add_additionals(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->additional_count<DNS_MAX_RRS){ dns_resource_record_t *rr=&m->additionals[m->additional_count++]; memset(rr,0,sizeof(*rr)); rr->packet_type=DNS_RESOURCE_RECORD; rr->present=1; rr->name_len=1; rr->name[0]=0; rr->type=41; rr->class_code=4096; rr->ttl=0; rr->rdlength=0; rr->rdata_len=0; } }}
void delete_additionals(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->additional_count>0){ m->additional_count--; } }}
void repeat_additionals(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->additional_count==0) continue; if(m->additional_count<DNS_MAX_RRS){ m->additionals[m->additional_count]=m->additionals[m->additional_count-1]; m->additional_count++; } }}
void mutate_additionals(dns_packet_t *pkts, size_t n){ uint32_t seed=0xCAFEBABEu; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; for(uint16_t j=0;j<m->additional_count;j++) mutate_rr(&m->additionals[j], &seed); }}

// opt_rr and has_opt: optional, single
void add_opt_rr(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; m->has_opt=1; dns_opt_record_t *o=&m->opt_rr; memset(o,0,sizeof(*o)); o->packet_type=DNS_OPT_RECORD; o->present=1; o->name_len=1; o->name[0]=0; o->type=41; o->udp_payload_size=4096; o->ext_rcode=0; o->edns_version=0; o->edns_flags=0; o->rdlength=0; o->rdata_len=0; }}
void delete_opt_rr(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ pkts[i].u.dns_message.has_opt=0; pkts[i].u.dns_message.opt_rr.present=0; }}
void mutate_opt_rr(dns_packet_t *pkts, size_t n){ uint32_t seed=0xDEADBEEFu; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(!m->has_opt) continue; dns_opt_record_t *o=&m->opt_rr; switch(prng_u32(&seed)%8){ case 0: o->udp_payload_size ^= (uint16_t)prng_u32(&seed); break; case 1: o->ext_rcode ^= (uint8_t)prng_u32(&seed); break; case 2: o->edns_version ^= (uint8_t)prng_u32(&seed); break; case 3: o->edns_flags ^= (uint16_t)prng_u32(&seed); break; case 4: if(o->rdata_len<DNS_MAX_OPT_RDATA){ o->rdata[o->rdata_len++]=(uint8_t)prng_u32(&seed); o->rdlength=o->rdata_len; } break; case 5: if(o->rdata_len>0){ o->rdata_len--; o->rdlength=o->rdata_len; } break; case 6: o->name_len = 1; o->name[0]=0; break; case 7: m->has_opt ^= 1; o->present = m->has_opt; break; } }}

static void dns_sync_opt_rdata(dns_opt_record_t *o) {
    if (!o) return;
    uint16_t off = 0;
    for (uint16_t j = 0; j < o->option_count && j < DNS_MAX_EDNS_OPTIONS; j++) {
        dns_edns_option_t *op = &o->options[j];
        if (!op->present) continue;
        uint16_t len = op->data_len;
        if (len > DNS_MAX_OPT_RDATA) len = DNS_MAX_OPT_RDATA;
        if ((uint32_t)off + 4u + len > DNS_MAX_OPT_RDATA) break;
        o->rdata[off++] = (uint8_t)(op->option_code >> 8);
        o->rdata[off++] = (uint8_t)op->option_code;
        o->rdata[off++] = (uint8_t)(len >> 8);
        o->rdata[off++] = (uint8_t)len;
        if (len) { memcpy(o->rdata + off, op->data, len); off = (uint16_t)(off + len); }
        op->option_length = len;
    }
    o->rdata_len = off;
    o->rdlength = off;
}

void mutate_edns_options(dns_packet_t *pkts, size_t n){ uint32_t seed=0x68916891u; static const uint16_t codes[]={3,5,6,7,8,10,11,12,13,14,15}; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(!m->has_opt) continue; dns_opt_record_t *o=&m->opt_rr; if(o->option_count==0){ o->option_count=1; o->options[0].present=1; o->options[0].option_code=10; o->options[0].data_len=8; memcpy(o->options[0].data,"LEMURDNS",8); } for(uint16_t j=0;j<o->option_count && j<DNS_MAX_EDNS_OPTIONS;j++){ dns_edns_option_t *op=&o->options[j]; switch(prng_u32(&seed)%9){ case 0: op->option_code=codes[prng_u32(&seed)%(sizeof(codes)/sizeof(codes[0]))]; break; case 1: if(op->data_len<DNS_MAX_OPT_RDATA){ op->data[op->data_len++]=(uint8_t)prng_u32(&seed); } break; case 2: if(op->data_len>0){ op->data_len--; } break; case 3: op->present=1; break; case 4: if(op->data_len) op->data[0]^=(uint8_t)prng_u32(&seed); break; case 5: op->option_code=12; op->data_len=(uint16_t)((prng_u32(&seed)%24u)&~1u); memset(op->data,0,op->data_len); break; case 6: op->option_code=8; op->data_len=8; op->data[0]=0; op->data[1]=1; op->data[2]=24; op->data[3]=0; op->data[4]=192; op->data[5]=0; op->data[6]=2; op->data[7]=0; break; case 7: op->option_code=10; op->data_len=8; memcpy(op->data,"LEMURDNS",8); break; default: op->option_code=15; op->data_len=2; op->data[0]=0; op->data[1]=0; break; } op->option_length=op->data_len; } dns_sync_opt_rdata(o); }}

void mutate_edns_profile(dns_packet_t *pkts, size_t n){ static unsigned int profile; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; m->has_opt=1; dns_opt_record_t *o=&m->opt_rr; memset(o,0,sizeof(*o)); o->packet_type=DNS_OPT_RECORD; o->present=1; o->name_len=1; o->name[0]=0; o->type=41; static const uint16_t payloads[]={512,1232,1410,4096}; o->udp_payload_size=payloads[profile%(sizeof(payloads)/sizeof(payloads[0]))]; o->edns_version=0; o->edns_flags=(profile&1)?0x8000:0; uint16_t p=(uint16_t)(profile++%6); o->option_count=1; o->options[0].present=1; switch(p){ case 0: o->options[0].option_code=3; o->options[0].data_len=0; break; case 1: o->options[0].option_code=10; o->options[0].data_len=8; memcpy(o->options[0].data,"LEMURDNS",8); break; case 2: o->options[0].option_code=12; o->options[0].data_len=16; memset(o->options[0].data,0,16); break; case 3: o->options[0].option_code=8; o->options[0].data_len=8; o->options[0].data[1]=1; o->options[0].data[2]=24; o->options[0].data[4]=192; o->options[0].data[6]=2; break; case 4: o->options[0].option_code=11; o->options[0].data_len=2; o->options[0].data[0]=0; o->options[0].data[1]=30; break; default: o->options[0].option_code=15; o->options[0].data_len=2; o->options[0].data[0]=0; o->options[0].data[1]=0; break; } dns_sync_opt_rdata(o); m->header.arcount=(uint16_t)(m->additional_count+1); }}

void add_dso_tlv(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; m->header.opcode=6; m->question_count=m->answer_count=m->authority_count=m->additional_count=0; m->has_opt=0; if(m->dso_tlv_count<DNS_MAX_DSO_TLVS){ dns_dso_tlv_t *t=&m->dso_tlvs[m->dso_tlv_count++]; memset(t,0,sizeof(*t)); t->present=1; t->tlv_type=1; t->tlv_length=8; t->data_len=8; } }}
void delete_dso_tlv(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->dso_tlv_count>0) m->dso_tlv_count--; }}
void repeat_dso_tlv(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->dso_tlv_count && m->dso_tlv_count<DNS_MAX_DSO_TLVS){ m->dso_tlvs[m->dso_tlv_count]=m->dso_tlvs[m->dso_tlv_count-1]; m->dso_tlv_count++; } }}
void mutate_dso_tlv(dns_packet_t *pkts, size_t n){ uint32_t seed=0x84908490u; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; if(m->header.opcode!=6) continue; for(uint16_t j=0;j<m->dso_tlv_count && j<DNS_MAX_DSO_TLVS;j++){ dns_dso_tlv_t *t=&m->dso_tlvs[j]; switch(prng_u32(&seed)%9){ case 0: t->tlv_type^=(uint16_t)prng_u32(&seed); break; case 1: t->present^=1; break; case 2: if(t->data_len<DNS_MAX_DSO_DATA){ t->data[t->data_len++]=(uint8_t)prng_u32(&seed); t->tlv_length=t->data_len; } break; case 3: if(t->data_len>0){ t->data_len--; t->tlv_length=t->data_len; } break; case 4: t->tlv_length^=(uint16_t)prng_u32(&seed); break; case 5: for(uint16_t k=0;k<t->data_len;k++) if((prng_u32(&seed)&3)==0) t->data[k]^=(uint8_t)prng_u32(&seed); break; case 6: if(t->has_keepalive) t->inactivity_timeout^=prng_u32(&seed); break; case 7: if(t->has_keepalive) t->keepalive_interval^=prng_u32(&seed); break; default: t->tlv_type=(uint16_t)((t->tlv_type%3)+1); break; } } }}

static void dns_set_name(dns_question_t *q, const char *label) {
    if (!q) return;
    q->name_len = 0;
    if (!label || !*label || strcmp(label, ".") == 0) {
        q->name[q->name_len++] = 0;
        return;
    }
    const char *p = label;
    while (*p && q->name_len + 1 < DNS_MAX_NAME_LEN) {
        const char *dot = strchr(p, '.');
        size_t part = dot ? (size_t)(dot - p) : strlen(p);
        if (part > 63) part = 63;
        if (q->name_len + 1 + part >= DNS_MAX_NAME_LEN) break;
        q->name[q->name_len++] = (uint8_t)part;
        memcpy(q->name + q->name_len, p, part);
        q->name_len = (uint16_t)(q->name_len + part);
        if (!dot) break;
        p = dot + 1;
    }
    if (q->name_len == 0 || q->name[q->name_len - 1] != 0) {
        if (q->name_len < DNS_MAX_NAME_LEN) q->name[q->name_len++] = 0;
        else { q->name[0] = 0; q->name_len = 1; }
    }
}

static void dns_ensure_one_question(dns_message_t *m) {
    if (!m) return;
    if (m->question_count == 0) {
        memset(&m->questions[0], 0, sizeof(m->questions[0]));
        m->question_count = 1;
    }
    m->questions[0].packet_type = DNS_QUESTION;
    m->questions[0].present = 1;
    if (m->questions[0].name_len == 0) {
        m->questions[0].name[0] = 0;
        m->questions[0].name_len = 1;
    }
    if (m->questions[0].qclass == 0) m->questions[0].qclass = 1;
    if (m->questions[0].qtype == 0) m->questions[0].qtype = 1;
}

void mutate_dns_request_template(dns_packet_t *pkts, size_t n) {
    static unsigned int template_selector;
    const size_t template_count = sizeof(dns_query_templates) / sizeof(dns_query_templates[0]);
    for (size_t i = 0; i < n; i++) if (pkts[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkts[i].u.dns_message;
        dns_ensure_one_question(m);
        dns_question_t *q = &m->questions[0];
        const dns_query_template_t *tpl = &dns_query_templates[template_selector++ % template_count];

        m->header.qr = 0;
        m->header.opcode = 0;
        m->header.z = 0;
        m->header.rcode = 0;
        m->header.ra = 0;
        m->header.tc = 0;
        m->header.aa = 0;
        m->header.rd = tpl->rd & 1u;
        m->question_count = 1;
        m->answer_count = 0;
        m->authority_count = 0;
        m->additional_count = 0;
        memset(m->answers, 0, sizeof(m->answers));
        memset(m->authorities, 0, sizeof(m->authorities));
        memset(m->additionals, 0, sizeof(m->additionals));
        m->dso_tlv_count = 0;

        q->packet_type = DNS_QUESTION;
        q->present = 1;
        q->qtype = tpl->qtype;
        q->qclass = tpl->qclass;
        dns_set_name(q, tpl->name);

        if (tpl->edns) {
            m->has_opt = 1;
            dns_opt_record_t *o = &m->opt_rr;
            memset(o, 0, sizeof(*o));
            o->packet_type = DNS_OPT_RECORD;
            o->present = 1;
            o->name_len = 1;
            o->name[0] = 0;
            o->type = 41;
            o->udp_payload_size = tpl->edns_payload ? tpl->edns_payload : 1232;
            o->ext_rcode = 0;
            o->edns_version = 0;
            o->edns_flags = tpl->edns_flags;
            o->rdlength = 0;
            o->rdata_len = 0;
            o->option_count = 0;
        } else {
            m->has_opt = 0;
            memset(&m->opt_rr, 0, sizeof(m->opt_rr));
        }

        m->header.qdcount = 1;
        m->header.ancount = 0;
        m->header.nscount = 0;
        m->header.arcount = (uint16_t)(m->has_opt ? 1 : 0);
    }
}


// wire/wire_len: optional preserved bytes; mutate to explore equivalence without breaking storage
void add_wire(dns_packet_t *pkts, size_t n){ (void)pkts; (void)n; }
void delete_wire(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ pkts[i].u.dns_message.wire_len=0; }}
void mutate_wire(dns_packet_t *pkts, size_t n){ uint32_t seed=0x31415926u; for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_MESSAGE){ dns_message_t *m=&pkts[i].u.dns_message; for(uint16_t j=0;j<m->wire_len && j<DNS_MAX_WIRE;j++){ if((prng_u32(&seed)&7)==0) m->wire[j]^=(uint8_t)prng_u32(&seed); } }}

// DNS_HEADER per-field mutators

void mutate_id(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x11111111u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){
        dns_header_t *h=&pkts[i].u.dns_header;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: h->id = (uint16_t)(r); break; // random mix
            case 1: h->id ^= (uint16_t)(r>>1); break; // equivalence xor
            case 2: h->id = 0; break; // boundary low
            case 3: h->id = 0xFFFFu; break; // boundary high
            case 4: h->id = bswap16(h->id); break; // encoding/equivalence
            case 5: h->id += 1; break; // small step
            case 6: h->id -= 1; break; // small step
            case 7: h->id = (uint16_t)((h->id&0xFF00u) | (r&0xFF)); break; // suffix byte perturb
        }
    }
}

void mutate_qr(dns_packet_t *pkts, size_t n){
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ dns_header_t *h=&pkts[i].u.dns_header; h->qr ^= 1; }}

void mutate_opcode(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x22222222u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){
        dns_header_t *h=&pkts[i].u.dns_header;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: h->opcode = 0; break; // canonical QUERY
            case 1: h->opcode = (uint8_t)((h->opcode+1)&0xF); break; // cycle
            case 2: h->opcode = 15; break; // boundary high
            case 3: h->opcode = (uint8_t)(r & 0xF); break; // random allowed
            case 4: h->opcode ^= 0xF; h->opcode &= 0xF; break; // equivalence
            case 5: h->opcode = 2; break; // STATUS per RFC1035 historical
            case 6: h->opcode = 4; break; // reserved/extension space
            case 7: h->opcode = (uint8_t)((h->opcode==0)?5:0); break; // alt class
        }
    }
}

void mutate_aa(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ pkts[i].u.dns_header.aa ^= 1; }}
void mutate_tc(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ pkts[i].u.dns_header.tc ^= 1; }}
void mutate_rd(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ pkts[i].u.dns_header.rd ^= 1; }}
void mutate_ra(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ pkts[i].u.dns_header.ra ^= 1; }}

void mutate_z(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x33333333u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){
        dns_header_t *h=&pkts[i].u.dns_header;
        uint32_t r=prng_u32(&seed);
        switch(r%6){
            case 0: h->z = 0; break; // canonical reserved
            case 1: h->z = (uint8_t)(r & 0x7); break; // random 3-bit
            case 2: h->z ^= 0x7; h->z &= 0x7; break; // invert mask
            case 3: h->z = 7; break; // boundary
            case 4: h->z = 1; break; // minimal nonzero
            case 5: h->z = (uint8_t)((h->z<<1)&7); break; // shift shape
        }
    }
}

void mutate_rcode(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x44444444u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){
        dns_header_t *h=&pkts[i].u.dns_header;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: h->rcode = 0; break; // NOERROR canonical
            case 1: h->rcode = 3; break; // NXDOMAIN
            case 2: h->rcode = 2; break; // SERVFAIL
            case 3: h->rcode = 1; break; // FORMERR
            case 4: h->rcode = (uint8_t)(r & 0xF); break; // random allowed
            case 5: h->rcode = 15; break; // boundary high
            case 6: h->rcode = (uint8_t)((h->rcode+1)&0xF); break; // cycle
            case 7: h->rcode ^= 0xF; h->rcode &= 0xF; break; // equivalence invert
        }
    }
}

void mutate_qdcount(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x55555555u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){
        dns_header_t *h=&pkts[i].u.dns_header; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: h->qdcount = 0; break; // canonical boundary
            case 1: h->qdcount = 1; break;
            case 2: h->qdcount = 0xFFFFu; break; // boundary high
            case 3: h->qdcount += 1; break; // small inc
            case 4: h->qdcount -= 1; break; // small dec
            case 5: h->qdcount ^= (uint16_t)r; break; // random mix
            case 6: h->qdcount = (uint16_t)(r & 0x1F); break; // small random
            case 7: h->qdcount = bswap16(h->qdcount); break; // encoding variant
        }
    }
}
void mutate_ancount(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x66666666u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ dns_header_t *h=&pkts[i].u.dns_header; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: h->ancount=0; break; case 1: h->ancount=1; break; case 2: h->ancount=0xFFFFu; break; case 3: h->ancount+=1; break; case 4: h->ancount-=1; break; case 5: h->ancount^=(uint16_t)r; break; case 6: h->ancount=(uint16_t)(r&0x1F); break; case 7: h->ancount=bswap16(h->ancount); break; } }}
void mutate_nscount(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x77777777u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ dns_header_t *h=&pkts[i].u.dns_header; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: h->nscount=0; break; case 1: h->nscount=1; break; case 2: h->nscount=0xFFFFu; break; case 3: h->nscount+=1; break; case 4: h->nscount-=1; break; case 5: h->nscount^=(uint16_t)r; break; case 6: h->nscount=(uint16_t)(r&0x1F); break; case 7: h->nscount=bswap16(h->nscount); break; } }}
void mutate_arcount(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x88888888u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_HEADER){ dns_header_t *h=&pkts[i].u.dns_header; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: h->arcount=0; break; case 1: h->arcount=1; break; case 2: h->arcount=0xFFFFu; break; case 3: h->arcount+=1; break; case 4: h->arcount-=1; break; case 5: h->arcount^=(uint16_t)r; break; case 6: h->arcount=(uint16_t)(r&0x1F); break; case 7: h->arcount=bswap16(h->arcount); break; } }}

// DNS_QUESTION per-field mutators

// Fields: packet_type (not mutable), name_len, name[], qtype, qclass, present (optional helper)

void mutate_name_len(dns_packet_t *pkts, size_t n){
    uint32_t seed=0x90909090u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){
        dns_question_t *q=&pkts[i].u.dns_question;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: q->name_len = 0; break; // boundary: empty
            case 1: q->name_len = 1; q->name[0]=0; break; // canonical root
            case 2: q->name_len = (uint16_t)((r % (DNS_MAX_NAME_LEN+1))); break; // random within limit
            case 3: if(q->name_len<DNS_MAX_NAME_LEN) q->name_len++; break; // small inc
            case 4: if(q->name_len>0) q->name_len--; break; // small dec
            case 5: q->name_len = 255; if(q->name_len>DNS_MAX_NAME_LEN) q->name_len=DNS_MAX_NAME_LEN; break; // high boundary
            case 6: q->name_len ^= (uint16_t)(r & 0xFF); if(q->name_len>DNS_MAX_NAME_LEN) q->name_len=DNS_MAX_NAME_LEN; break; // equivalence xor
            case 7: { // align to even/odd as padding-alike
                uint16_t aligned = (uint16_t)((r&1)? (q->name_len|1) : (q->name_len & ~1));
                q->name_len = (aligned<=DNS_MAX_NAME_LEN)?aligned:q->name_len;
            } break;
        }
    }
}

void mutate_name(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xA0A0A0A0u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){
        dns_question_t *q=&pkts[i].u.dns_question;
        if(q->name_len==0){ q->name_len=1; q->name[0]=0; }
        uint16_t lim = q->name_len; if(lim>DNS_MAX_NAME_LEN) lim = DNS_MAX_NAME_LEN;
        for(uint16_t j=0;j<lim;j++){
            uint32_t r=prng_u32(&seed);
            if((r & 7)==0) q->name[j]^=(uint8_t)r; // random mix shallow
        }
        switch(prng_u32(&seed)%8){
            case 0: if(q->name_len<DNS_MAX_NAME_LEN){ // suffix: trailing root label
                        q->name[q->name_len++]=0;
                    } break;
            case 1: if(q->name_len+2<=DNS_MAX_NAME_LEN){ // prefix: add length octet 1 and 'a'
                        memmove(&q->name[2], &q->name[0], q->name_len);
                        q->name[0]=1; q->name[1]='a'; q->name_len+=2;
                    } break;
            case 2: if(q->name_len>1){ // trim suffix
                        q->name_len-=1;
                    } break;
            case 3: { // encoding-shape: set first label length coherent if possible
                        if(q->name_len>0){ uint8_t l = (uint8_t)((prng_u32(&seed)%10)); q->name[0]=l; if((uint16_t)(1+l)<=q->name_len){ for(uint8_t k=1;k<=l && k<q->name_len;k++){ q->name[k] = (uint8_t)('a'+(k%26)); } }}
                    } break;
            case 4: { // equivalence: toggle case letters in body
                        for(uint16_t j=0;j<lim;j++){ uint8_t c=q->name[j]; if(c>='a'&&c<='z') q->name[j]=c-32; else if(c>='A'&&c<='Z') q->name[j]=c+32; }
                    } break;
            case 5: { // boundaries: fill with zeros up to current len
                        for(uint16_t j=0;j<lim;j++) q->name[j]=0; }
                    break;
            case 6: { // random valid mix: sprinkle punctuation safely
                        for(uint16_t j=1;j<lim;j++){ if((prng_u32(&seed)&15)==0) q->name[j]='-'; }
                    } break;
            case 7: { // pad/alignment: ensure even length by adding a pad byte
                        if((q->name_len & 1) && q->name_len<DNS_MAX_NAME_LEN){ q->name[q->name_len++]=0; }
                    } break;
        }
    }
}

void add_present(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){ pkts[i].u.dns_question.present=1; }}
void delete_present(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){ pkts[i].u.dns_question.present=0; }}
void mutate_present(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){ pkts[i].u.dns_question.present ^= 1; }}

void mutate_qtype(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xB0B0B0B0u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){
        dns_question_t *q=&pkts[i].u.dns_question; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: q->qtype = 1; break; // A
            case 1: q->qtype = 28; break; // AAAA
            case 2: q->qtype = 15; break; // MX
            case 3: q->qtype = 255; break; // ANY
            case 4: q->qtype = 0; break; // boundary low
            case 5: q->qtype = 0xFFFFu; break; // boundary high
            case 6: q->qtype = bswap16(q->qtype); break; // equivalence endian
            case 7: q->qtype ^= (uint16_t)r; break; // random mix
        }
    }
}

void mutate_qclass(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xC0C0C0C0u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_QUESTION){
        dns_question_t *q=&pkts[i].u.dns_question; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: q->qclass = 1; break; // IN
            case 1: q->qclass = 3; break; // CH
            case 2: q->qclass = 4; break; // HS
            case 3: q->qclass = 255; break; // ANY
            case 4: q->qclass = 0; break; // boundary low
            case 5: q->qclass = 0xFFFFu; break; // boundary high
            case 6: q->qclass = bswap16(q->qclass); break; // equivalence endian
            case 7: q->qclass ^= (uint16_t)r; break; // random mix
        }
    }
}

// DNS_RESOURCE_RECORD per-field mutators
// Fields: packet_type (not mutable), name_len, name[], type, class_code, ttl, rdlength, rdata_len, rdata[], present (optional)

void mutate_name_len_rr(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD1D1D1D1u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){
        dns_resource_record_t *rr=&pkts[i].u.dns_rr;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: rr->name_len=1; rr->name[0]=0; break; // canonical root
            case 1: rr->name_len=0; break; // boundary empty
            case 2: rr->name_len=(uint16_t)(r % (DNS_MAX_NAME_LEN+1)); break; // random within bounds
            case 3: if(rr->name_len<DNS_MAX_NAME_LEN) rr->name_len++; break; // small inc
            case 4: if(rr->name_len>0) rr->name_len--; break; // small dec
            case 5: rr->name_len=DNS_MAX_NAME_LEN; break; // high boundary
            case 6: rr->name_len ^= (uint16_t)(r & 0xFF); if(rr->name_len>DNS_MAX_NAME_LEN) rr->name_len=DNS_MAX_NAME_LEN; break; // xor equiv
            case 7: { uint16_t aligned = (uint16_t)((r&1)?(rr->name_len|1):(rr->name_len&~1)); rr->name_len = (aligned<=DNS_MAX_NAME_LEN)?aligned:rr->name_len; } break; // padding-like
        }
    }
}

void mutate_name_rr(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD2D2D2D2u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){
        dns_resource_record_t *rr=&pkts[i].u.dns_rr;
        if(rr->name_len==0){ rr->name_len=1; rr->name[0]=0; }
        uint16_t lim=rr->name_len; if(lim>DNS_MAX_NAME_LEN) lim=DNS_MAX_NAME_LEN;
        for(uint16_t j=0;j<lim;j++){ uint32_t r=prng_u32(&seed); if((r&7)==0) rr->name[j]^=(uint8_t)r; }
        switch(prng_u32(&seed)%8){
            case 0: if(rr->name_len<DNS_MAX_NAME_LEN) rr->name[rr->name_len++]=0; break; // suffix root label
            case 1: if(rr->name_len+2<=DNS_MAX_NAME_LEN){ memmove(&rr->name[2], &rr->name[0], rr->name_len); rr->name[0]=1; rr->name[1]='b'; rr->name_len+=2; } break; // prefix label
            case 2: if(rr->name_len>0) rr->name_len--; break; // trim
            case 3: if(rr->name_len>0){ uint8_t l=(uint8_t)(prng_u32(&seed)%10); rr->name[0]=l; for(uint8_t k=1;k<=l && k<rr->name_len;k++){ rr->name[k]=(uint8_t)('n'+(k%26)); } } break; // encoding-shape
            case 4: for(uint16_t j=0;j<lim;j++){ uint8_t c=rr->name[j]; if(c>='a'&&c<='z') rr->name[j]=c-32; else if(c>='A'&&c<='Z') rr->name[j]=c+32; } break; // case alt
            case 5: for(uint16_t j=0;j<lim;j++) rr->name[j]=0; break; // zero fill
            case 6: for(uint16_t j=1;j<lim;j++){ if((prng_u32(&seed)&15)==0) rr->name[j]='-'; } break; // sprinkle dash
            case 7: if((rr->name_len&1) && rr->name_len<DNS_MAX_NAME_LEN){ rr->name[rr->name_len++]=0; } break; // pad to even
        }
    }
}

void mutate_type(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD3D3D3D3u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ dns_resource_record_t *rr=&pkts[i].u.dns_rr; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: rr->type=1; break; case 1: rr->type=2; break; case 2: rr->type=5; break; case 3: rr->type=28; break; case 4: rr->type=0; break; case 5: rr->type=0xFFFFu; break; case 6: rr->type=bswap16(rr->type); break; case 7: rr->type^=(uint16_t)r; break; } }}

void mutate_class_code(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD4D4D4D4u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ dns_resource_record_t *rr=&pkts[i].u.dns_rr; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: rr->class_code=1; break; case 1: rr->class_code=3; break; case 2: rr->class_code=4; break; case 3: rr->class_code=255; break; case 4: rr->class_code=0; break; case 5: rr->class_code=0xFFFFu; break; case 6: rr->class_code=bswap16(rr->class_code); break; case 7: rr->class_code^=(uint16_t)r; break; } }}

void mutate_ttl(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD5D5D5D5u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ dns_resource_record_t *rr=&pkts[i].u.dns_rr; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: rr->ttl=0; break; case 1: rr->ttl=1; break; case 2: rr->ttl=0xFFFFFFFFu; break; case 3: rr->ttl+=1; break; case 4: rr->ttl^=r; break; case 5: rr->ttl=bswap32(rr->ttl); break; case 6: rr->ttl=(r&0x00FFFFFFu); break; case 7: rr->ttl=(r|0x80000000u); break; } }}

void mutate_rdlength(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD6D6D6D6u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ dns_resource_record_t *rr=&pkts[i].u.dns_rr; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: rr->rdlength=0; rr->rdata_len=0; break; case 1: rr->rdlength=1; rr->rdata_len=(rr->rdata_len<1)?1:rr->rdata_len; break; case 2: rr->rdlength=(uint16_t)((r % (DNS_MAX_RDATA+1))); break; case 3: rr->rdlength^=(uint16_t)r; break; case 4: rr->rdlength=0xFFFFu; break; case 5: rr->rdlength=bswap16(rr->rdlength); break; case 6: if(rr->rdlength<DNS_MAX_RDATA) rr->rdlength++; break; case 7: if(rr->rdlength>0) rr->rdlength--; break; } }}

void mutate_rdata_len(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD7D7D7D7u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ dns_resource_record_t *rr=&pkts[i].u.dns_rr; uint32_t r=prng_u32(&seed); switch(r%8){ case 0: rr->rdata_len=0; break; case 1: rr->rdata_len=1; break; case 2: rr->rdata_len=(uint16_t)(r % (DNS_MAX_RDATA+1)); break; case 3: rr->rdata_len^=(uint16_t)r; break; case 4: rr->rdata_len=DNS_MAX_RDATA; break; case 5: if(rr->rdata_len<DNS_MAX_RDATA) rr->rdata_len++; break; case 6: if(rr->rdata_len>0) rr->rdata_len--; break; case 7: rr->rdata_len=bswap16(rr->rdata_len); break; } if(rr->rdlength>rr->rdata_len) rr->rdlength=rr->rdata_len; }}

void mutate_rdata(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xD8D8D8D8u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ dns_resource_record_t *rr=&pkts[i].u.dns_rr; uint16_t lim=rr->rdata_len; if(lim>DNS_MAX_RDATA) lim=DNS_MAX_RDATA; for(uint16_t j=0;j<lim;j++){ uint32_t r=prng_u32(&seed); if((r&7)==0) rr->rdata[j]^=(uint8_t)r; } switch(prng_u32(&seed)%8){ case 0: if(rr->rdata_len<DNS_MAX_RDATA){ rr->rdata[rr->rdata_len++]=(uint8_t)prng_u32(&seed); rr->rdlength=rr->rdata_len; } break; case 1: if(rr->rdata_len>0){ rr->rdata_len--; rr->rdlength=rr->rdata_len; } break; case 2: if(rr->rdata_len>=2){ uint8_t t=rr->rdata[0]; rr->rdata[0]=rr->rdata[1]; rr->rdata[1]=t; } break; case 3: if(rr->rdata_len>0){ rr->rdata[0]^=0xFF; } break; case 4: for(uint16_t j=0;j<lim;j++) rr->rdata[j]=0; break; case 5: if(rr->rdata_len+2<=DNS_MAX_RDATA){ rr->rdata[rr->rdata_len++]=0; rr->rdata[rr->rdata_len++]=0; rr->rdlength=rr->rdata_len; } break; case 6: if(rr->rdata_len>2){ rr->rdata_len-=2; rr->rdlength=rr->rdata_len; } break; case 7: ; break; } }}

void add_present_rr(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ pkts[i].u.dns_rr.present=1; }}
void delete_present_rr(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ pkts[i].u.dns_rr.present=0; }}
void mutate_present_rr(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_RESOURCE_RECORD){ pkts[i].u.dns_rr.present ^= 1; }}

// DNS_OPT_RECORD per-field mutators
// Fields: packet_type (not mutable), name_len (not mutable per EDNS: root label), name (not mutable), type (not mutable: 41),
// udp_payload_size, ext_rcode, edns_version, edns_flags, rdlength, rdata_len, rdata, present (optional)

void mutate_udp_payload_size(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE1E1E1E1u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->udp_payload_size = 512; break; // canonical RFC1035 UDP size
            case 1: o->udp_payload_size = 1232; break; // common safe size
            case 2: o->udp_payload_size = 4096; break; // typical EDNS
            case 3: o->udp_payload_size = 65535; break; // max boundary
            case 4: o->udp_payload_size ^= (uint16_t)r; break; // random mix
            case 5: o->udp_payload_size = bswap16(o->udp_payload_size); break; // encoding alt
            case 6: if(o->udp_payload_size>0) o->udp_payload_size--; else o->udp_payload_size=1; break; // boundary step
            case 7: o->udp_payload_size += 1; break; // small inc
        }
    }
}

void mutate_ext_rcode(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE2E2E2E2u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->ext_rcode = 0; break; // canonical
            case 1: o->ext_rcode = 1; break;
            case 2: o->ext_rcode = 15; break; // boundary of base space
            case 3: o->ext_rcode = (uint8_t)r; break; // random
            case 4: o->ext_rcode ^= 0xFF; break; // invert
            case 5: o->ext_rcode |= 0x80; break; // set high bit
            case 6: o->ext_rcode &= 0x7F; break; // clear high bit
            case 7: o->ext_rcode = (uint8_t)((o->ext_rcode+1)&0xFF); break; // cycle
        }
    }
}

void mutate_edns_version(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE3E3E3E3u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->edns_version = 0; break; // canonical EDNS(0)
            case 1: o->edns_version = 1; break; // hypothetical future
            case 2: o->edns_version = 255; break; // boundary
            case 3: o->edns_version = (uint8_t)r; break; // random
            case 4: o->edns_version ^= 0xFF; break;
            case 5: o->edns_version |= 0x80; break;
            case 6: o->edns_version &= 0x7F; break;
            case 7: o->edns_version = (uint8_t)((o->edns_version+1)&0xFF); break;
        }
    }
}

void mutate_edns_flags(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE4E4E4E4u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->edns_flags = 0; break; // canonical
            case 1: o->edns_flags ^= 0x8000; break; // DO bit toggle
            case 2: o->edns_flags |= 0x8000; break; // set DO
            case 3: o->edns_flags &= (uint16_t)~0x8000; break; // clear DO
            case 4: o->edns_flags = (uint16_t)r; break; // random
            case 5: o->edns_flags = bswap16(o->edns_flags); break; // encoding alt
            case 6: o->edns_flags ^= 0xFFFF; break; // invert
            case 7: o->edns_flags |= 0x4000; break; // set another high bit
        }
    }
}

void mutate_rdlength_opt(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE5E5E5E5u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->rdlength=0; o->rdata_len=0; break;
            case 1: o->rdlength=1; if(o->rdata_len<1) o->rdata_len=1; break;
            case 2: o->rdlength=(uint16_t)(r % (DNS_MAX_OPT_RDATA+1)); break;
            case 3: o->rdlength^=(uint16_t)r; break;
            case 4: o->rdlength=0xFFFFu; break;
            case 5: o->rdlength=bswap16(o->rdlength); break;
            case 6: if(o->rdlength<DNS_MAX_OPT_RDATA) o->rdlength++; break;
            case 7: if(o->rdlength>0) o->rdlength--; break;
        }
        if(o->rdlength>o->rdata_len) o->rdlength=o->rdata_len;
    }
}

void mutate_rdata_len_opt(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE6E6E6E6u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt; uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->rdata_len=0; break;
            case 1: o->rdata_len=1; break;
            case 2: o->rdata_len=(uint16_t)(r % (DNS_MAX_OPT_RDATA+1)); break;
            case 3: o->rdata_len^=(uint16_t)r; break;
            case 4: o->rdata_len=DNS_MAX_OPT_RDATA; break;
            case 5: if(o->rdata_len<DNS_MAX_OPT_RDATA) o->rdata_len++; break;
            case 6: if(o->rdata_len>0) o->rdata_len--; break;
            case 7: o->rdata_len=bswap16(o->rdata_len); break;
        }
        if(o->rdlength>o->rdata_len) o->rdlength=o->rdata_len;
    }
}

void mutate_rdata_opt(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xE7E7E7E7u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){
        dns_opt_record_t *o=&pkts[i].u.dns_opt;
        uint16_t lim=o->rdata_len; if(lim>DNS_MAX_OPT_RDATA) lim=DNS_MAX_OPT_RDATA;
        for(uint16_t j=0;j<lim;j++){ uint32_t r=prng_u32(&seed); if((r&7)==0) o->rdata[j]^=(uint8_t)r; }
        switch(prng_u32(&seed)%8){
            case 0: if(o->rdata_len<DNS_MAX_OPT_RDATA){ o->rdata[o->rdata_len++]=(uint8_t)prng_u32(&seed); o->rdlength=o->rdata_len; } break;
            case 1: if(o->rdata_len>0){ o->rdata_len--; o->rdlength=o->rdata_len; } break;
            case 2: if(o->rdata_len>=4){ // swap first opt code/len bytes
                        uint8_t t=o->rdata[0]; o->rdata[0]=o->rdata[1]; o->rdata[1]=t; t=o->rdata[2]; o->rdata[2]=o->rdata[3]; o->rdata[3]=t; }
                    break;
            case 3: if(o->rdata_len>=2){ o->rdata[0]^=0xFF; o->rdata[1]^=0x0F; } break;
            case 4: for(uint16_t j=0;j<lim;j++) o->rdata[j]=0; break;
            case 5: if(o->rdata_len+4<=DNS_MAX_OPT_RDATA){ // inject minimal TLV padding
                        o->rdata[o->rdata_len++]=0; o->rdata[o->rdata_len++]=0; o->rdata[o->rdata_len++]=0; o->rdata[o->rdata_len++]=0; o->rdlength=o->rdata_len; }
                    break;
            case 6: if(o->rdata_len>4){ o->rdata_len-=4; o->rdlength=o->rdata_len; } break;
            case 7: ; break;
        }
    }
}

void add_present_opt(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){ pkts[i].u.dns_opt.present=1; }}
void delete_present_opt(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){ pkts[i].u.dns_opt.present=0; }}
void mutate_present_opt(dns_packet_t *pkts, size_t n){ for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPT_RECORD){ pkts[i].u.dns_opt.present ^= 1; }}

// DNS_OPAQUE_RDATA per-field mutators
// Fields: packet_type (not mutable), rdlength, rdata_len, rdata[]

void mutate_rdlength_opaque(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xF1F1F1F1u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPAQUE_RDATA){
        dns_opaque_rdata_t *o=&pkts[i].u.dns_opaque;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->rdlength=0; break; // canonical empty
            case 1: o->rdlength=1; break; // small
            case 2: o->rdlength=(uint16_t)(r % (DNS_MAX_RDATA+1)); break; // random within bounds
            case 3: o->rdlength^=(uint16_t)r; break; // equivalence xor
            case 4: o->rdlength=0xFFFFu; break; // boundary high
            case 5: o->rdlength=bswap16(o->rdlength); break; // encoding variant
            case 6: if(o->rdlength<DNS_MAX_RDATA) o->rdlength++; break; // inc
            case 7: if(o->rdlength>0) o->rdlength--; break; // dec
        }
        if(o->rdlength>o->rdata_len) o->rdlength=o->rdata_len;
    }
}

void mutate_rdata_len_opaque(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xF2F2F2F2u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPAQUE_RDATA){
        dns_opaque_rdata_t *o=&pkts[i].u.dns_opaque;
        uint32_t r=prng_u32(&seed);
        switch(r%8){
            case 0: o->rdata_len=0; break;
            case 1: o->rdata_len=1; break;
            case 2: o->rdata_len=(uint16_t)(r % (DNS_MAX_RDATA+1)); break;
            case 3: o->rdata_len^=(uint16_t)r; break;
            case 4: o->rdata_len=DNS_MAX_RDATA; break;
            case 5: if(o->rdata_len<DNS_MAX_RDATA) o->rdata_len++; break;
            case 6: if(o->rdata_len>0) o->rdata_len--; break;
            case 7: o->rdata_len=bswap16(o->rdata_len); break;
        }
        if(o->rdlength>o->rdata_len) o->rdlength=o->rdata_len;
    }
}

void mutate_rdata_opaque(dns_packet_t *pkts, size_t n){
    uint32_t seed=0xF3F3F3F3u;
    for(size_t i=0;i<n;i++) if(pkts[i].type==DNS_OPAQUE_RDATA){
        dns_opaque_rdata_t *o=&pkts[i].u.dns_opaque;
        uint16_t lim=o->rdata_len; if(lim>DNS_MAX_RDATA) lim=DNS_MAX_RDATA;
        for(uint16_t j=0;j<lim;j++){ uint32_t r=prng_u32(&seed); if((r&7)==0) o->rdata[j]^=(uint8_t)r; }
        switch(prng_u32(&seed)%8){
            case 0: if(o->rdata_len<DNS_MAX_RDATA){ o->rdata[o->rdata_len++]=(uint8_t)prng_u32(&seed); o->rdlength=o->rdata_len; } break;
            case 1: if(o->rdata_len>0){ o->rdata_len--; o->rdlength=o->rdata_len; } break;
            case 2: if(o->rdata_len>=2){ uint8_t t=o->rdata[0]; o->rdata[0]=o->rdata[1]; o->rdata[1]=t; } break;
            case 3: for(uint16_t j=0;j<lim;j++) o->rdata[j]=0; o->rdlength=o->rdata_len; break;
            case 4: if(o->rdata_len+2<=DNS_MAX_RDATA){ o->rdata[o->rdata_len++]=0; o->rdata[o->rdata_len++]=0; o->rdlength=o->rdata_len; } break;
            case 5: if(o->rdata_len>2){ o->rdata_len-=2; o->rdlength=o->rdata_len; } break;
            case 6: if(o->rdata_len>0){ o->rdata[0]^=0xFF; } break;
            case 7: ; break;
        }
    }
}

void dispatch_dns_mutation(dns_packet_t *pkts, unsigned int pkt_count) {
    static unsigned int selector;
    if (!pkts || pkt_count == 0) return;
    dns_packet_t *p = &pkts[selector++ % pkt_count];
    if (p->type == DNS_MESSAGE) p->u.dns_message.wire_len = 0;

    switch (p->type) {
        case DNS_MESSAGE:
            switch (selector % 22) {
                case 0: mutate_dns_request_template(p, 1); break;
                case 1: mutate_dns_request_template(p, 1); break;
                case 2: mutate_dns_request_template(p, 1); break;
                case 3: mutate_dns_request_template(p, 1); break;
                case 4: mutate_questions(p, 1); break;
                case 5: mutate_questions(p, 1); break;
                case 6: mutate_header(p, 1); break;
                case 7: add_opt_rr(p, 1); break;
                case 8: mutate_opt_rr(p, 1); break;
                case 9: mutate_edns_options(p, 1); break;
                case 10: delete_opt_rr(p, 1); break;
                case 11: mutate_dns_request_template(p, 1); break;
                case 12: mutate_questions(p, 1); break;
                case 13: add_questions(p, 1); break;
                case 14: repeat_questions(p, 1); break;
                case 15: mutate_additionals(p, 1); break;
                case 16: add_additionals(p, 1); break;
                case 17: mutate_dns_request_template(p, 1); break;
                case 18: mutate_dns_request_template(p, 1); break;
                case 19: mutate_edns_profile(p, 1); break;
                case 20: mutate_edns_options(p, 1); break;
                default: mutate_questions(p, 1); break;
            }
            break;
        case DNS_HEADER:
            switch (selector % 11) {
                case 0: mutate_id(p, 1); break;
                case 1: mutate_qr(p, 1); break;
                case 2: mutate_opcode(p, 1); break;
                case 3: mutate_aa(p, 1); break;
                case 4: mutate_tc(p, 1); break;
                case 5: mutate_rd(p, 1); break;
                case 6: mutate_ra(p, 1); break;
                case 7: mutate_z(p, 1); break;
                case 8: mutate_rcode(p, 1); break;
                case 9: mutate_qdcount(p, 1); break;
                default: mutate_arcount(p, 1); break;
            }
            break;
        case DNS_QUESTION:
            switch (selector % 7) {
                case 0: mutate_name_len(p, 1); break;
                case 1: mutate_name(p, 1); break;
                case 2: add_present(p, 1); break;
                case 3: delete_present(p, 1); break;
                case 4: mutate_present(p, 1); break;
                case 5: mutate_qtype(p, 1); break;
                default: mutate_qclass(p, 1); break;
            }
            break;
        case DNS_RESOURCE_RECORD:
            switch (selector % 11) {
                case 0: mutate_name_len_rr(p, 1); break;
                case 1: mutate_name_rr(p, 1); break;
                case 2: mutate_type(p, 1); break;
                case 3: mutate_class_code(p, 1); break;
                case 4: mutate_ttl(p, 1); break;
                case 5: mutate_rdlength(p, 1); break;
                case 6: mutate_rdata_len(p, 1); break;
                case 7: mutate_rdata(p, 1); break;
                case 8: add_present_rr(p, 1); break;
                case 9: delete_present_rr(p, 1); break;
                default: mutate_present_rr(p, 1); break;
            }
            break;
        case DNS_OPT_RECORD:
            switch (selector % 10) {
                case 0: mutate_udp_payload_size(p, 1); break;
                case 1: mutate_ext_rcode(p, 1); break;
                case 2: mutate_edns_version(p, 1); break;
                case 3: mutate_edns_flags(p, 1); break;
                case 4: mutate_rdlength_opt(p, 1); break;
                case 5: mutate_rdata_len_opt(p, 1); break;
                case 6: mutate_rdata_opt(p, 1); break;
                case 7: add_present_opt(p, 1); break;
                case 8: delete_present_opt(p, 1); break;
                default: mutate_present_opt(p, 1); break;
            }
            break;
        case DNS_OPAQUE_RDATA:
            switch (selector % 3) {
                case 0: mutate_rdlength_opaque(p, 1); break;
                case 1: mutate_rdata_len_opaque(p, 1); break;
                default: mutate_rdata_opaque(p, 1); break;
            }
            break;
        default:
            break;
    }
}

void dispatch_dns_multiple_mutations(dns_packet_t *pkts, unsigned int pkt_count,
                                     unsigned int rounds) {
    if (!pkts || pkt_count == 0) return;
    if (rounds == 0) rounds = 1;
    for (unsigned int i = 0; i < rounds; ++i) {
        dispatch_dns_mutation(pkts, pkt_count);
    }
}
