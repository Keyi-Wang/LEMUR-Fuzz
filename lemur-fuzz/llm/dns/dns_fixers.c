// dns_fixers.c
// Fixers to enforce DNS request (client-to-server) message constraints.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "dns_packets.h"

// Helper: validate and sanitize an on-the-wire domain name buffer in place.
// Ensures: sequence of labels, each length <=63, terminates with 0, total <=255,
// and no compression pointers are used (rewrites to root if any invalidity found).
static void sanitize_name(uint8_t *name, uint16_t *name_len) {
    if (!name || !name_len) return;
    uint16_t len = *name_len;
    if (len == 0 || len > DNS_MAX_NAME_LEN) { name[0] = 0; *name_len = 1; return; }

    uint16_t off = 0;
    uint16_t steps = 0;
    int ok = 1;
    while (off < len) {
        if (++steps > DNS_MAX_LABELS) { ok = 0; break; }
        uint8_t l = name[off];
        // Compression pointer not allowed in fixer output for names; sanitize if seen
        if ((l & 0xC0) == 0xC0) { ok = 0; break; }
        off++;
        if (l == 0) {
            // Must be the end; trailing bytes beyond declared len are ignored; ensure end is exactly here
            // Truncate any trailing garbage
            *name_len = off;
            break;
        }
        if (l > 63) { ok = 0; break; }
        if ((uint32_t)off + l > len) { ok = 0; break; }
        off = (uint16_t)(off + l);
        if (off > DNS_MAX_NAME_LEN) { ok = 0; break; }
        if (off == len) {
            // Missing root terminator; we'll append below if space
            break;
        }
    }

    if (!ok) {
        name[0] = 0; *name_len = 1; return;
    }

    // Ensure terminated with root label 0
    if (*name_len == 0 || name[*name_len - 1] != 0) {
        if (*name_len < DNS_MAX_NAME_LEN) {
            name[(*name_len)++] = 0;
        } else {
            // No room, collapse to root
            name[0] = 0; *name_len = 1;
        }
    }
    // Ensure total length <= 255 already bounded by DNS_MAX_NAME_LEN
    if (*name_len > DNS_MAX_NAME_LEN) {
        name[0] = 0; *name_len = 1;
    }
}

static void compact_rr_array(dns_resource_record_t *arr, uint16_t *count) {
    if (!arr || !count) return;
    uint16_t in = *count, out = 0;
    for (uint16_t i = 0; i < in && i < DNS_MAX_RRS; i++) {
        if (arr[i].present || (arr[i].name_len || arr[i].rdlength)) {
            if (out != i) arr[out] = arr[i];
            out++;
        }
    }
    *count = out;
}

static void compact_question_array(dns_question_t *arr, uint16_t *count) {
    if (!arr || !count) return;
    uint16_t in = *count, out = 0;
    for (uint16_t i = 0; i < in && i < DNS_MAX_QUESTIONS; i++) {
        if (arr[i].present || (arr[i].name_len || arr[i].qtype || arr[i].qclass)) {
            if (out != i) arr[out] = arr[i];
            out++;
        }
    }
    *count = out;
}

static uint16_t clamp16u(uint32_t v) { return (uint16_t)(v & 0xFFFFu); }

static void set_wire_name(uint8_t *dst, uint16_t *dst_len, const char *label) {
    if (!dst || !dst_len) return;
    *dst_len = 0;
    if (!label || !*label || strcmp(label, ".") == 0) {
        dst[(*dst_len)++] = 0;
        return;
    }
    const char *p = label;
    while (*p && *dst_len + 1 < DNS_MAX_NAME_LEN) {
        const char *dot = strchr(p, '.');
        size_t part = dot ? (size_t)(dot - p) : strlen(p);
        if (part > 63) part = 63;
        if (*dst_len + 1 + part >= DNS_MAX_NAME_LEN) break;
        dst[(*dst_len)++] = (uint8_t)part;
        memcpy(dst + *dst_len, p, part);
        *dst_len = (uint16_t)(*dst_len + part);
        if (!dot) break;
        p = dot + 1;
    }
    if (*dst_len == 0 || dst[*dst_len - 1] != 0) {
        if (*dst_len < DNS_MAX_NAME_LEN) dst[(*dst_len)++] = 0;
        else { dst[0] = 0; *dst_len = 1; }
    }
}

static void ensure_question(dns_message_t *m) {
    if (!m) return;
    if (m->question_count == 0) {
        memset(&m->questions[0], 0, sizeof(m->questions[0]));
        m->question_count = 1;
    }
    dns_question_t *q = &m->questions[0];
    q->packet_type = DNS_QUESTION;
    q->present = 1;
    if (q->name_len == 0) set_wire_name(q->name, &q->name_len, "example.com");
    if (q->qtype == 0 || q->qtype == 252) q->qtype = 1;
    if (q->qclass == 0) q->qclass = 1;
}

// [RFC1035-4.1.1] QR MUST be 0 in a request (query).
void fix_RFC1035_4_1_1_QR_is_query(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        m->header.qr = 0;
    }
}

// [RFC1035-4.1.1] Z (reserved) field MUST be zero in all queries and responses.
void fix_RFC1035_4_1_1_Z_zero(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        pkt[i].u.dns_message.header.z = 0;
    }
}

// [RFC1035-4.1.1] ID MUST be a 16-bit identifier assigned by the requester; it is copied into the response.
// Our struct already limits to 16 bits; ensure no further action.
void fix_RFC1035_4_1_1_ID_16bit(dns_packet_t *pkt, int num_packets) {
    (void)pkt; (void)num_packets; // No-op: field is uint16_t
}

// [RFC1035-4.1.1] RD (Recursion Desired) MAY be set in a query and is copied into the response.
// No strict requirement to modify; ensure it's 0 or 1.
void fix_RFC1035_4_1_1_RD_bit(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        pkt[i].u.dns_message.header.rd &= 1;
    }
}

// [RFC1035-4.1.1] OPCODE is a 4-bit operation code. RFC-defined request
// operations modeled here are QUERY(0), IQUERY(1), STATUS(2), NOTIFY(4), and UPDATE(5).
void fix_RFC1035_4_1_1_opcode_known_request(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_header_t *h = &pkt[i].u.dns_message.header;
        h->opcode &= 0x0F;
        if (!(h->opcode == 0 || h->opcode == 1 || h->opcode == 2 ||
              h->opcode == 4 || h->opcode == 5)) {
            h->opcode = 0;
        }
    }
}

// [RFC1035-4.1.1] AA is meaningful in responses. Client requests must not set it.
void fix_RFC1035_4_1_1_AA_not_in_query(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        if (pkt[i].u.dns_message.header.qr == 0) pkt[i].u.dns_message.header.aa = 0;
        else pkt[i].u.dns_message.header.aa &= 1;
    }
}

// [RFC1035-4.1.1] RA is response-only; MUST NOT be set by requester in a query.
void fix_RFC1035_4_1_1_RA_not_in_query(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if (m->header.qr == 0) m->header.ra = 0;
        else m->header.ra &= 1; // if response present, keep as 0/1
    }
}

// [RFC1035-4.1.1] RCODE is response-only; MUST be zero in a query.
void fix_RFC1035_4_1_1_RCODE_zero_in_query(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        if (pkt[i].u.dns_message.header.qr == 0) pkt[i].u.dns_message.header.rcode = 0;
        else pkt[i].u.dns_message.header.rcode &= 0xF;
    }
}

// [RFC1035-4.1.2] Question section encodes exactly QNAME, QTYPE, QCLASS.
// Ensure presence flags and sanitize QNAME encoding; leave QTYPE/QCLASS as-is.
void fix_RFC1035_4_1_2_question_format(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        for (uint16_t q = 0; q < m->question_count && q < DNS_MAX_QUESTIONS; q++) {
            dns_question_t *qu = &m->questions[q];
            qu->present = 1; // ensure marked
            sanitize_name(qu->name, &qu->name_len);
        }
    }
}

// [RFC1035-2.3.4] QNAME label length <=63, name length <=255. Enforced via sanitize_name
void fix_RFC1035_2_3_4_label_and_name_lengths(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        for (uint16_t q = 0; q < m->question_count && q < DNS_MAX_QUESTIONS; q++) {
            sanitize_name(m->questions[q].name, &m->questions[q].name_len);
        }
        for (uint16_t j = 0; j < m->answer_count && j < DNS_MAX_RRS; j++) {
            sanitize_name(m->answers[j].name, &m->answers[j].name_len);
        }
        for (uint16_t j = 0; j < m->authority_count && j < DNS_MAX_RRS; j++) {
            sanitize_name(m->authorities[j].name, &m->authorities[j].name_len);
        }
        for (uint16_t j = 0; j < m->additional_count && j < DNS_MAX_RRS; j++) {
            sanitize_name(m->additionals[j].name, &m->additionals[j].name_len);
        }
        if (m->has_opt) sanitize_name(m->opt_rr.name, &m->opt_rr.name_len);
    }
}

// [RFC1035-3.1, 2.3.4] Names must be labels ending with root. Enforced via sanitize_name
void fix_RFC1035_3_1_wire_name_sequence(dns_packet_t *pkt, int num_packets) {
    // Already covered by sanitize_name for all sections
    fix_RFC1035_2_3_4_label_and_name_lengths(pkt, num_packets);
}

// [RFC1035-3.1] High two bits of length octet MUST be zero unless compression pointer. We disallow pointers in fixer.
void fix_RFC1035_3_1_length_octet_highbits(dns_packet_t *pkt, int num_packets) {
    // Already enforced by sanitize_name which collapses on detecting pointers or invalid high bits.
    fix_RFC1035_2_3_4_label_and_name_lengths(pkt, num_packets);
}

// [RFC1035-4.1.4] If compression is used, pointers must point backward. Fixer removes compression by normalizing names.
void fix_RFC1035_4_1_4_compression_pointers(dns_packet_t *pkt, int num_packets) {
    // Remove/avoid pointers by sanitizing names to uncompressed form or root if invalid.
    fix_RFC1035_2_3_4_label_and_name_lengths(pkt, num_packets);
}

// [RFC1035-4.2.1] UDP without EDNS limited to 512; longer responses truncated and TC set.
// For queries, just ensure TC is 0; however to be conservative, if no OPT present, we clear TC in queries.
void fix_RFC1035_4_2_1_udp_512_and_tc(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if (m->header.qr == 0) {
            // Queries should not be truncated; clear TC bit.
            m->header.tc = 0;
        }
    }
}

// [RFC1035-4.2.1] UDP MUST NOT be used for zone transfers (AXFR). Convert AXFR QTYPE to a safer value (A) in queries.
void fix_RFC1035_4_2_1_no_AXFR_over_udp(dns_packet_t *pkt, int num_packets) {
    /* Keep AXFR in the wire message.  dnsmasq deliberately has an error and
     * TCP-only path for AXFR/IXFR; mapping it to A here removed that path from
     * the semantic stage.  The transport harness already uses UDP, so the
     * server can reject the request naturally. */
    (void)pkt; (void)num_packets;
}

// [RFC1035-3.2.3] QTYPE MUST be a valid QTYPE. If out of typical range, map to ANY (255).
void fix_RFC1035_3_2_3_qtype_valid(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        for (uint16_t q = 0; q < m->question_count && q < DNS_MAX_QUESTIONS; q++) {
            uint16_t t = m->questions[q].qtype;
            if (t == 0) m->questions[q].qtype = 1; /* TYPE 0 is not a query type. */
        }
    }
}

void fix_DNS_query_shape_for_udp_dnsmasq(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if (m->header.qr != 0 || m->header.opcode != 0) continue;
        ensure_question(m);
        /* Keep additional questions and sections: dnsmasq has distinct
         * multi-question, malformed-section, and AXFR handling paths.  The
         * previous fixer collapsed all of those into one A/IN question. */
        for (uint16_t q = 0; q < m->question_count && q < DNS_MAX_QUESTIONS; q++) {
            m->questions[q].present = 1;
            sanitize_name(m->questions[q].name, &m->questions[q].name_len);
            if (m->questions[q].qtype == 0) m->questions[q].qtype = 1;
            if (m->questions[q].qclass == 0) m->questions[q].qclass = 1;
        }
        m->header.rd &= 1;
        m->header.aa = 0;
        m->header.tc = 0;
        m->header.ra = 0;
        m->header.z = 0;
        m->header.rcode = 0;
    }
}

// [RFC1996-3] NOTIFY is carried as an opcode with a normal DNS question for
// the zone being notified. Keep one SOA question so a server sees a valid NOTIFY request.
void fix_RFC1996_3_NOTIFY_question_section(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if ((m->header.opcode & 0x0F) != 4) continue;
        if (m->question_count == 0) {
            memset(&m->questions[0], 0, sizeof(m->questions[0]));
            m->questions[0].present = 1;
            m->questions[0].name_len = 1;
            m->questions[0].name[0] = 0;
            m->question_count = 1;
        }
        if (m->question_count > 1) m->question_count = 1;
        m->questions[0].present = 1;
        sanitize_name(m->questions[0].name, &m->questions[0].name_len);
        m->questions[0].qtype = 6;  // SOA
        if (m->questions[0].qclass == 0) m->questions[0].qclass = 1;
    }
}

// [RFC2136-2.3] UPDATE reuses the DNS header counts as ZOCOUNT/PRCOUNT/UPCOUNT/ADCOUNT;
// the Zone section is exactly one question whose ZTYPE is SOA.
void fix_RFC2136_2_UPDATE_zone_section(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if ((m->header.opcode & 0x0F) != 5) continue;
        if (m->question_count == 0) {
            memset(&m->questions[0], 0, sizeof(m->questions[0]));
            m->questions[0].present = 1;
            m->questions[0].name_len = 1;
            m->questions[0].name[0] = 0;
            m->question_count = 1;
        }
        if (m->question_count > 1) m->question_count = 1;
        m->questions[0].present = 1;
        sanitize_name(m->questions[0].name, &m->questions[0].name_len);
        m->questions[0].qtype = 6;  // ZTYPE=SOA
        if (m->questions[0].qclass == 0) m->questions[0].qclass = 1;
    }
}

// EDNS(0) fixers per RFC6891

// [RFC6891-6.1.2] At most one OPT RR; if multiple, keep first and remove others.
void fix_RFC6891_6_1_2_single_OPT(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        // Detect OPT in additionals array
        int found = m->has_opt && m->opt_rr.present;
        // If no explicit opt_rr, search additionals and populate
        for (uint16_t j = 0; j < m->additional_count && j < DNS_MAX_RRS; j++) {
            if (m->additionals[j].type == 41) {
                if (!found) {
                    // Populate opt_rr from generic RR
                    dns_resource_record_t *grr = &m->additionals[j];
                    m->has_opt = 1; m->opt_rr.present = 1;
                    m->opt_rr.packet_type = DNS_OPT_RECORD;
                    m->opt_rr.name_len = grr->name_len;
                    memcpy(m->opt_rr.name, grr->name, grr->name_len > DNS_MAX_NAME_LEN ? DNS_MAX_NAME_LEN : grr->name_len);
                    m->opt_rr.type = 41;
                    m->opt_rr.udp_payload_size = grr->class_code;
                    uint32_t ttl = grr->ttl;
                    m->opt_rr.ext_rcode = (uint8_t)((ttl >> 24) & 0xFF);
                    m->opt_rr.edns_version = (uint8_t)((ttl >> 16) & 0xFF);
                    m->opt_rr.edns_flags = (uint16_t)(ttl & 0xFFFF);
                    m->opt_rr.rdlength = grr->rdlength;
                    uint16_t to_copy = grr->rdata_len; if (to_copy > DNS_MAX_OPT_RDATA) to_copy = DNS_MAX_OPT_RDATA;
                    m->opt_rr.rdata_len = to_copy;
                    if (to_copy) memcpy(m->opt_rr.rdata, grr->rdata, to_copy);
                    found = 1;
                }
                // Remove duplicate OPT from additionals by clearing presence
                m->additionals[j].present = 0;
                m->additionals[j].name_len = 0;
                m->additionals[j].rdlength = 0;
                m->additionals[j].rdata_len = 0;
            }
        }
        // Compact additionals after removals
        compact_rr_array(m->additionals, &m->additional_count);
        // If more than one explicit opt_rr somehow, we only ever keep one per struct.
    }
}

// [RFC6891-6.1.2] OPT RR MUST be in Additional section. Our model keeps opt_rr separately; ensure has_opt implies not counted in header counts incorrectly.
void fix_RFC6891_6_1_2_OPT_in_additional(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        // No action needed beyond removing from non-additional sections; ensure none exist there.
        dns_message_t *m = &pkt[i].u.dns_message;
        for (uint16_t j = 0; j < m->answer_count; j++) if (m->answers[j].type == 41) { m->answers[j].present = 0; m->answers[j].name_len = 0; m->answers[j].rdlength = 0; m->answers[j].rdata_len = 0; }
        for (uint16_t j = 0; j < m->authority_count; j++) if (m->authorities[j].type == 41) { m->authorities[j].present = 0; m->authorities[j].name_len = 0; m->authorities[j].rdlength = 0; m->authorities[j].rdata_len = 0; }
        compact_rr_array(m->answers, &m->answer_count);
        compact_rr_array(m->authorities, &m->authority_count);
    }
}

// [RFC6891-6.1.2] OPT NAME MUST be root (0) and TYPE MUST be 41; CLASS carries payload size; TTL encodes ext_rcode/version/flags.
void fix_RFC6891_6_1_2_OPT_shape(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if (!m->has_opt || !m->opt_rr.present) continue;
        dns_opt_record_t *o = &m->opt_rr;
        // Name root
        o->name_len = 1; o->name[0] = 0;
        // Type
        o->type = 41;
        // Reasonable payload size (at least 512)
        if (o->udp_payload_size < 512) o->udp_payload_size = 512;
        // TTL parts are already separated; ensure flags are within 16-bit and ext fields 8-bit
        o->ext_rcode &= 0xFF; o->edns_version &= 0xFF; o->edns_flags &= 0xFFFF;
        // rdlength must match the OPTION-DATA vector length.
        if (o->rdata_len > DNS_MAX_OPT_RDATA) o->rdata_len = DNS_MAX_OPT_RDATA;
        o->rdlength = o->rdata_len;
        if (o->option_count > DNS_MAX_EDNS_OPTIONS) o->option_count = DNS_MAX_EDNS_OPTIONS;
        uint32_t rebuilt = 0;
        for (uint16_t j = 0; j < o->option_count; j++) {
            dns_edns_option_t *op = &o->options[j];
            if (op->data_len > DNS_MAX_OPT_RDATA) op->data_len = DNS_MAX_OPT_RDATA;
            op->option_length = op->data_len;
            op->present = 1;
            rebuilt += 4u + op->data_len;
        }
        if (o->option_count && rebuilt <= DNS_MAX_OPT_RDATA) o->rdlength = o->rdata_len = (uint16_t)rebuilt;
    }
}

// [RFC6891-6.1.4] In OPT flags, Z bits MUST be zero; keep DO bit.
void fix_RFC6891_6_1_4_OPT_flags_Z_zero(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if (!m->has_opt || !m->opt_rr.present) continue;
        uint16_t do_bit = (uint16_t)(m->opt_rr.edns_flags & 0x8000u);
        m->opt_rr.edns_flags = do_bit; // clear all except DO
    }
}

// [RFC6891-6.2.1] OPT RR MUST NOT be cached (not applicable at message format level) -> no-op
void fix_RFC6891_6_2_1_no_cache(dns_packet_t *pkt, int num_packets) { (void)pkt; (void)num_packets; }

// [RFC6891-6.2.2] Fallback behavior (not a wire constraint) -> no-op
void fix_RFC6891_6_2_2_fallback(dns_packet_t *pkt, int num_packets) { (void)pkt; (void)num_packets; }

void fix_RFC8490_DSO_header_and_tlv_lengths(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        if (m->header.opcode != 6) continue;
        m->header.qdcount = 0;
        m->header.ancount = 0;
        m->header.nscount = 0;
        m->header.arcount = 0;
        m->question_count = 0;
        m->answer_count = 0;
        m->authority_count = 0;
        m->additional_count = 0;
        m->has_opt = 0;
        if (m->dso_tlv_count > DNS_MAX_DSO_TLVS) m->dso_tlv_count = DNS_MAX_DSO_TLVS;
        for (uint16_t j = 0; j < m->dso_tlv_count; j++) {
            dns_dso_tlv_t *t = &m->dso_tlvs[j];
            if (t->data_len > DNS_MAX_DSO_DATA) t->data_len = DNS_MAX_DSO_DATA;
            if (t->has_keepalive) {
                t->tlv_type = 1;
                t->tlv_length = 8;
                t->data_len = 8;
            } else {
                t->tlv_length = t->data_len;
            }
            t->present = 1;
        }
    }
}

// Synchronize header counts to actual in-struct counts and ensure bounds.
static void fix_counts_to_arrays(dns_message_t *m) {
    if (!m) return;
    // Compact arrays to drop cleared entries
    compact_question_array(m->questions, &m->question_count);
    compact_rr_array(m->answers, &m->answer_count);
    compact_rr_array(m->authorities, &m->authority_count);
    compact_rr_array(m->additionals, &m->additional_count);

    if (m->question_count > DNS_MAX_QUESTIONS) m->question_count = DNS_MAX_QUESTIONS;
    if (m->answer_count > DNS_MAX_RRS) m->answer_count = DNS_MAX_RRS;
    if (m->authority_count > DNS_MAX_RRS) m->authority_count = DNS_MAX_RRS;
    if (m->additional_count > DNS_MAX_RRS) m->additional_count = DNS_MAX_RRS;

    m->header.qdcount = clamp16u(m->question_count);
    m->header.ancount = clamp16u(m->answer_count);
    m->header.nscount = clamp16u(m->authority_count);
    // arcount should reflect generic additional RRs; OPT is not separately counted in header in classic RFC1035,
    // but on the wire, OPT counts as one RR in the additional section. We'll include it if present.
    uint16_t ar = m->additional_count;
    if (m->has_opt && m->opt_rr.present) ar = (uint16_t)(ar + 1);
    m->header.arcount = clamp16u(ar);
}


static uint32_t emit_name(uint8_t *dst, uint32_t cap, const uint8_t *name, uint16_t len) {
    uint16_t n = len;
    sanitize_name((uint8_t *)name, &n); /* safe for model-owned arrays */
    if (n > cap) return 0;
    memcpy(dst, name, n);
    return n;
}

static void sync_typed_rdata(dns_resource_record_t *rr) {
    if (!rr || !rr->rdata_schema) return;
    uint8_t tmp[DNS_MAX_RDATA];
    uint32_t off = 0;
    switch (rr->rdata_schema) {
        case 1:
            rr->type = 1; rr->address_len = 4;
            memcpy(rr->rdata, rr->address, 4); rr->rdata_len = rr->rdlength = 4; return;
        case 28:
            rr->type = 28; rr->address_len = 16;
            memcpy(rr->rdata, rr->address, 16); rr->rdata_len = rr->rdlength = 16; return;
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12:
            if (rr->name_count < 1) return;
            off = emit_name(tmp, sizeof(tmp), rr->names[0].wire, rr->names[0].len);
            if (!off) return;
            memcpy(rr->rdata, tmp, off); rr->rdata_len = rr->rdlength = (uint16_t)off; return;
        case 15:
            if (rr->u16_count < 1 || rr->name_count < 1) return;
            tmp[off++] = (uint8_t)(rr->u16_values[0] >> 8); tmp[off++] = (uint8_t)rr->u16_values[0];
            { uint32_t n = emit_name(tmp + off, sizeof(tmp) - off, rr->names[0].wire, rr->names[0].len); if (!n) return; off += n; }
            memcpy(rr->rdata, tmp, off); rr->rdata_len = rr->rdlength = (uint16_t)off; return;
        case 16:
            for (uint8_t i = 0; i < rr->string_count && i < DNS_MAX_RDATA_STRINGS; i++) {
                uint16_t len = rr->strings[i].len; if (len > 255) len = 255;
                if (off + 1u + len > sizeof(tmp)) break;
                tmp[off++] = (uint8_t)len;
                memcpy(tmp + off, rr->strings[i].data, len); off += len;
            }
            if (off) { memcpy(rr->rdata, tmp, off); rr->rdata_len = rr->rdlength = (uint16_t)off; }
            return;
        case 33:
            if (rr->u16_count < 3 || rr->name_count < 1) return;
            for (uint8_t i = 0; i < 3; i++) { tmp[off++] = (uint8_t)(rr->u16_values[i] >> 8); tmp[off++] = (uint8_t)rr->u16_values[i]; }
            { uint32_t n = emit_name(tmp + off, sizeof(tmp) - off, rr->names[0].wire, rr->names[0].len); if (!n) return; off += n; }
            memcpy(rr->rdata, tmp, off); rr->rdata_len = rr->rdlength = (uint16_t)off; return;
        default:
            return;
    }
}

// Ensure RDATA lengths are consistent with buffers for all RRs.
static void fix_rr_lengths(dns_message_t *m) {
    if (!m) return;
    for (uint16_t j = 0; j < m->answer_count && j < DNS_MAX_RRS; j++) {
        sync_typed_rdata(&m->answers[j]);
        if (m->answers[j].rdata_len > DNS_MAX_RDATA) m->answers[j].rdata_len = DNS_MAX_RDATA;
        m->answers[j].rdlength = m->answers[j].rdata_len;
    }
    for (uint16_t j = 0; j < m->authority_count && j < DNS_MAX_RRS; j++) {
        sync_typed_rdata(&m->authorities[j]);
        if (m->authorities[j].rdata_len > DNS_MAX_RDATA) m->authorities[j].rdata_len = DNS_MAX_RDATA;
        m->authorities[j].rdlength = m->authorities[j].rdata_len;
    }
    for (uint16_t j = 0; j < m->additional_count && j < DNS_MAX_RRS; j++) {
        sync_typed_rdata(&m->additionals[j]);
        if (m->additionals[j].rdata_len > DNS_MAX_RDATA) m->additionals[j].rdata_len = DNS_MAX_RDATA;
        m->additionals[j].rdlength = m->additionals[j].rdata_len;
    }
}

// [RFC1035-4.1.1] QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT must match the encoded sections.
void fix_RFC1035_4_1_1_count_fields_match_sections(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        fix_counts_to_arrays(&pkt[i].u.dns_message);
    }
}

// [RFC1035-4.1.3] Each RR RDLENGTH must equal the following RDATA length.
void fix_RFC1035_4_1_3_rr_rdlength_matches_rdata(dns_packet_t *pkt, int num_packets) {
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        fix_rr_lengths(&pkt[i].u.dns_message);
        if (pkt[i].u.dns_message.has_opt && pkt[i].u.dns_message.opt_rr.present) {
            dns_opt_record_t *o = &pkt[i].u.dns_message.opt_rr;
            if (o->rdata_len > DNS_MAX_OPT_RDATA) o->rdata_len = DNS_MAX_OPT_RDATA;
            o->rdlength = o->rdata_len;
        }
    }
}

// Top-level dispatcher to apply all fixers to DNS messages in array order.
void fix_dns(dns_packet_t *pkt, int num_packets) {
    if (!pkt || num_packets <= 0) return;

    // Apply header-level fixers for requests
    fix_RFC1035_4_1_1_QR_is_query(pkt, num_packets);
    fix_RFC1035_4_1_1_Z_zero(pkt, num_packets);
    fix_RFC1035_4_1_1_ID_16bit(pkt, num_packets);
    fix_RFC1035_4_1_1_RD_bit(pkt, num_packets);
    fix_RFC1035_4_1_1_opcode_known_request(pkt, num_packets);
    fix_RFC1035_4_1_1_AA_not_in_query(pkt, num_packets);
    fix_RFC1035_4_1_1_RA_not_in_query(pkt, num_packets);
    fix_RFC1035_4_1_1_RCODE_zero_in_query(pkt, num_packets);

    // Question and name encoding fixers
    fix_RFC1035_4_1_2_question_format(pkt, num_packets);
    fix_RFC1035_2_3_4_label_and_name_lengths(pkt, num_packets);
    fix_RFC1035_3_1_wire_name_sequence(pkt, num_packets);
    fix_RFC1035_3_1_length_octet_highbits(pkt, num_packets);
    fix_RFC1035_4_1_4_compression_pointers(pkt, num_packets);

    // UDP/AXFR related
    fix_RFC1035_4_2_1_udp_512_and_tc(pkt, num_packets);
    fix_RFC1035_4_2_1_no_AXFR_over_udp(pkt, num_packets);
    fix_RFC1035_3_2_3_qtype_valid(pkt, num_packets);
    fix_DNS_query_shape_for_udp_dnsmasq(pkt, num_packets);
    fix_RFC1996_3_NOTIFY_question_section(pkt, num_packets);
    fix_RFC2136_2_UPDATE_zone_section(pkt, num_packets);

    // EDNS fixers
    fix_RFC6891_6_1_2_single_OPT(pkt, num_packets);
    fix_RFC6891_6_1_2_OPT_in_additional(pkt, num_packets);
    fix_RFC6891_6_1_2_OPT_shape(pkt, num_packets);
    fix_RFC6891_6_1_4_OPT_flags_Z_zero(pkt, num_packets);
    fix_RFC6891_6_2_1_no_cache(pkt, num_packets);
    fix_RFC6891_6_2_2_fallback(pkt, num_packets);
    fix_RFC8490_DSO_header_and_tlv_lengths(pkt, num_packets);

    // Per-message consistency: sanitize names again post-EDNS shaping
    for (int i = 0; i < num_packets; i++) if (pkt[i].type == DNS_MESSAGE) {
        dns_message_t *m = &pkt[i].u.dns_message;
        // Sanitize all names
        for (uint16_t q = 0; q < m->question_count && q < DNS_MAX_QUESTIONS; q++) sanitize_name(m->questions[q].name, &m->questions[q].name_len);
        for (uint16_t j = 0; j < m->answer_count && j < DNS_MAX_RRS; j++) sanitize_name(m->answers[j].name, &m->answers[j].name_len);
        for (uint16_t j = 0; j < m->authority_count && j < DNS_MAX_RRS; j++) sanitize_name(m->authorities[j].name, &m->authorities[j].name_len);
        for (uint16_t j = 0; j < m->additional_count && j < DNS_MAX_RRS; j++) sanitize_name(m->additionals[j].name, &m->additionals[j].name_len);
        if (m->has_opt) sanitize_name(m->opt_rr.name, &m->opt_rr.name_len);
        // Fix RR length and count coherency
        fix_rr_lengths(m);
        fix_counts_to_arrays(m);
    }
    fix_RFC1035_4_1_3_rr_rdlength_matches_rdata(pkt, num_packets);
    fix_RFC1035_4_1_1_count_fields_match_sections(pkt, num_packets);
}
