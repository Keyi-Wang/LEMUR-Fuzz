// dns_packets.c
// Implementation of generate and print utilities for DNS packet model.

#include "dns_packets.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void init_header(dns_header_t *h) {
    memset(h, 0, sizeof(*h));
    h->packet_type = DNS_HEADER; /* Fixed */
}

static void init_question(dns_question_t *q) {
    memset(q, 0, sizeof(*q));
    q->packet_type = DNS_QUESTION; /* Fixed */
}

static void init_rr(dns_resource_record_t *rr) {
    memset(rr, 0, sizeof(*rr));
    rr->packet_type = DNS_RESOURCE_RECORD; /* Fixed */
}

static void init_opt(dns_opt_record_t *o) {
    memset(o, 0, sizeof(*o));
    o->packet_type = DNS_OPT_RECORD; /* Fixed */
}


static void init_message(dns_message_t *m) {
    memset(m, 0, sizeof(*m));
    m->packet_type = DNS_MESSAGE; /* Fixed */
    init_header(&m->header);
    for (int i = 0; i < DNS_MAX_QUESTIONS; ++i) init_question(&m->questions[i]);
    for (int i = 0; i < DNS_MAX_RRS; ++i) {
        init_rr(&m->answers[i]);
        init_rr(&m->authorities[i]);
        init_rr(&m->additionals[i]);
    }
    init_opt(&m->opt_rr);
    m->has_opt = 0;
}

// Public generator

dns_packet_t* generate_dns_packets(int count) {
    if (count <= 0) return NULL;
    dns_packet_t *packets = (dns_packet_t *)malloc(sizeof(dns_packet_t) * (size_t)count);
    if (!packets) return NULL;
    memset(packets, 0, sizeof(dns_packet_t) * (size_t)count);
    for (int i = 0; i < count; ++i) {
        packets[i].type = DNS_MESSAGE; /* default to message container */
        init_message(&packets[i].u.dns_message);
    }
    return packets;
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
        if ((i + 1) % 32 == 0) printf("\n");
        else if ((i + 1) % 2 == 0) printf(" ");
    }
    if (len) printf("\n");
}

static void print_header(const dns_header_t *h) {
    printf("  DNS_HEADER (packet_type=%u)\n", h->packet_type);
    printf("    id: 0x%04x\n", h->id);
    printf("    flags: qr=%u opcode=%u aa=%u tc=%u rd=%u ra=%u z=%u rcode=%u\n",
           h->qr, h->opcode, h->aa, h->tc, h->rd, h->ra, h->z, h->rcode);
    printf("    counts: qd=%u an=%u ns=%u ar=%u\n", h->qdcount, h->ancount, h->nscount, h->arcount);
}

static void print_question(const dns_question_t *q, const char *prefix) {
    printf("  %sDNS_QUESTION (packet_type=%u) present=%u\n", prefix, q->packet_type, q->present);
    printf("    qname_len=%u qname=", q->name_len);
    print_hex(q->name, q->name_len);
    printf("    qtype=%u qclass=%u\n", q->qtype, q->qclass);
}

static void print_rr(const dns_resource_record_t *rr, const char *prefix) {
    printf("  %sDNS_RESOURCE_RECORD (packet_type=%u) present=%u\n", prefix, rr->packet_type, rr->present);
    printf("    name_len=%u name=", rr->name_len);
    print_hex(rr->name, rr->name_len);
    printf("    type=%u class=%u ttl=%u\n", rr->type, rr->class_code, rr->ttl);
    printf("    rdlength=%u rdata_len=%u\n", rr->rdlength, rr->rdata_len);
    printf("    rdata=\n");
    print_hex(rr->rdata, rr->rdata_len);
}

static void print_opt(const dns_opt_record_t *o) {
    printf("  DNS_OPT_RECORD (packet_type=%u) present=%u\n", o->packet_type, o->present);
    printf("    name_len=%u name=", o->name_len);
    print_hex(o->name, o->name_len);
    printf("    type=%u udp_payload_size=%u\n", o->type, o->udp_payload_size);
    printf("    ext_rcode=%u edns_version=%u edns_flags=0x%04x\n", o->ext_rcode, o->edns_version, o->edns_flags);
    printf("    rdlength=%u rdata_len=%u\n", o->rdlength, o->rdata_len);
    printf("    rdata=\n");
    print_hex(o->rdata, o->rdata_len);
}

void print_dns_packets(const dns_packet_t *packets, int count) {
    if (!packets || count <= 0) return;
    for (int i = 0; i < count; ++i) {
        printf("DNS Packet %d:\n", i);
        const dns_message_t *m = &packets[i].u.dns_message;
        printf(" packet_type=%u (DNS_MESSAGE) wire_len=%u\n", m->packet_type, m->wire_len);
        print_header(&m->header);
        printf(" Questions (%u actual, header.qdcount=%u):\n", m->question_count, m->header.qdcount);
        for (uint16_t qi = 0; qi < m->question_count && qi < DNS_MAX_QUESTIONS; ++qi) {
            print_question(&m->questions[qi], "");
        }
        printf(" Answers (%u actual, header.ancount=%u):\n", m->answer_count, m->header.ancount);
        for (uint16_t ri = 0; ri < m->answer_count && ri < DNS_MAX_RRS; ++ri) {
            print_rr(&m->answers[ri], "");
        }
        printf(" Authorities (%u actual, header.nscount=%u):\n", m->authority_count, m->header.nscount);
        for (uint16_t ri = 0; ri < m->authority_count && ri < DNS_MAX_RRS; ++ri) {
            print_rr(&m->authorities[ri], "");
        }
        printf(" Additionals (%u actual, header.arcount=%u):\n", m->additional_count, m->header.arcount);
        for (uint16_t ri = 0; ri < m->additional_count && ri < DNS_MAX_RRS; ++ri) {
            print_rr(&m->additionals[ri], "");
        }
        if (m->has_opt) {
            print_opt(&m->opt_rr);
        }
        printf(" Original wire (%u bytes):\n", m->wire_len);
        print_hex(m->wire, m->wire_len);
    }
}
