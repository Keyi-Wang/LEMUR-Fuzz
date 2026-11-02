#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dns_packets.h"

#ifndef U8_U32_DEFINED
typedef unsigned char u8;
typedef unsigned int u32;
#endif

static int write_u8(u8 **p, u32 *remaining, u8 v) {
    if (*remaining < 1) return -1;
    **p = v;
    (*p)++;
    (*remaining)--;
    return 0;
}

static int write_u16(u8 **p, u32 *remaining, uint16_t v) {
    if (*remaining < 2) return -1;
    (*p)[0] = (u8)((v >> 8) & 0xFF);
    (*p)[1] = (u8)(v & 0xFF);
    (*p) += 2;
    (*remaining) -= 2;
    return 0;
}

static int write_u32(u8 **p, u32 *remaining, uint32_t v) {
    if (*remaining < 4) return -1;
    (*p)[0] = (u8)((v >> 24) & 0xFF);
    (*p)[1] = (u8)((v >> 16) & 0xFF);
    (*p)[2] = (u8)((v >> 8) & 0xFF);
    (*p)[3] = (u8)(v & 0xFF);
    (*p) += 4;
    (*remaining) -= 4;
    return 0;
}

static int write_bytes(u8 **p, u32 *remaining, const u8 *src, u32 len) {
    if (len == 0) return 0;
    if (src == NULL) return -1;
    if (*remaining < len) return -1;
    memcpy(*p, src, len);
    (*p) += len;
    (*remaining) -= len;
    return 0;
}

static uint16_t clamp_u16(uint32_t v) {
    return (uint16_t)(v & 0xFFFFu);
}

static uint16_t dns_valid_wire_name_len(const u8 *name, uint16_t name_len) {
    if (!name || name_len == 0 || name_len > DNS_MAX_NAME_LEN) return 0;

    uint16_t off = 0;
    uint16_t steps = 0;
    while (off < name_len) {
        if (++steps > DNS_MAX_LABELS) return 0;

        u8 lablen = name[off];
        if ((lablen & 0xC0) == 0xC0) {
            if ((uint32_t)off + 2 > name_len) return 0;
            return (uint16_t)(off + 2);
        }

        off++;
        if (lablen == 0) return off;
        if (lablen > 63) return 0;
        if ((uint32_t)off + lablen > name_len) return 0;
        off = (uint16_t)(off + lablen);
    }

    return 0;
}

static int write_dns_name(u8 **p, u32 *remaining, const u8 *name, uint16_t name_len) {
    uint16_t valid_len = dns_valid_wire_name_len(name, name_len);
    if (valid_len == 0) return write_u8(p, remaining, 0);
    return write_bytes(p, remaining, name, valid_len);
}

static int question_is_present(const dns_question_t *q) {
    return q && (q->present || q->name_len || q->qtype || q->qclass);
}

static int rr_is_present(const dns_resource_record_t *rr) {
    return rr && (rr->present || rr->name_len || rr->type || rr->class_code ||
                  rr->ttl || rr->rdlength || rr->rdata_len);
}

static uint16_t count_questions_to_write(const dns_message_t *m) {
    if (!m) return 0;
    uint16_t limit = m->question_count;
    if (limit > DNS_MAX_QUESTIONS) limit = DNS_MAX_QUESTIONS;
    uint16_t count = 0;
    for (uint16_t i = 0; i < limit; i++) {
        if (question_is_present(&m->questions[i])) count++;
    }
    return count;
}

static uint16_t count_rrs_to_write(const dns_resource_record_t *rrs, uint16_t rr_count) {
    if (!rrs) return 0;
    uint16_t limit = rr_count;
    if (limit > DNS_MAX_RRS) limit = DNS_MAX_RRS;
    uint16_t count = 0;
    for (uint16_t i = 0; i < limit; i++) {
        if (rr_is_present(&rrs[i])) count++;
    }
    return count;
}

static int opt_is_present(const dns_message_t *m) {
    return m && m->has_opt && m->opt_rr.present;
}

static int reassemble_dns_header(const dns_header_t *h, u8 **outp, u32 *remaining) {
    if (!h || !outp || !remaining) return -1;
    if (*remaining < 12) return -1;
    if (write_u16(outp, remaining, h->id)) return -1;
    uint16_t flags = 0;
    flags |= (uint16_t)((h->qr & 0x1) << 15);
    flags |= (uint16_t)((h->opcode & 0xF) << 11);
    flags |= (uint16_t)((h->aa & 0x1) << 10);
    flags |= (uint16_t)((h->tc & 0x1) << 9);
    flags |= (uint16_t)((h->rd & 0x1) << 8);
    flags |= (uint16_t)((h->ra & 0x1) << 7);
    flags |= (uint16_t)((h->z & 0x7) << 4);
    flags |= (uint16_t)(h->rcode & 0xF);
    if (write_u16(outp, remaining, flags)) return -1;
    if (write_u16(outp, remaining, h->qdcount)) return -1;
    if (write_u16(outp, remaining, h->ancount)) return -1;
    if (write_u16(outp, remaining, h->nscount)) return -1;
    if (write_u16(outp, remaining, h->arcount)) return -1;
    return 0;
}

static int reassemble_dns_question(const dns_question_t *q, u8 **outp, u32 *remaining) {
    if (!q || !outp || !remaining) return -1;
    uint16_t name_len = q->name_len;
    if (name_len > DNS_MAX_NAME_LEN) name_len = DNS_MAX_NAME_LEN;
    if (write_dns_name(outp, remaining, q->name, name_len)) return -1;
    if (write_u16(outp, remaining, q->qtype)) return -1;
    if (write_u16(outp, remaining, q->qclass)) return -1;
    return 0;
}

static int reassemble_dns_resource_record(const dns_resource_record_t *rr, u8 **outp, u32 *remaining) {
    if (!rr || !outp || !remaining) return -1;
    uint16_t name_len = rr->name_len;
    if (name_len > DNS_MAX_NAME_LEN) name_len = DNS_MAX_NAME_LEN;
    if (write_dns_name(outp, remaining, rr->name, name_len)) return -1;
    if (write_u16(outp, remaining, rr->type)) return -1;
    if (write_u16(outp, remaining, rr->class_code)) return -1;
    if (write_u32(outp, remaining, rr->ttl)) return -1;
    uint16_t rdlen = rr->rdata_len;
    const u8 *rdata = rr->rdata;
    if (rdlen > DNS_MAX_RDATA) rdlen = DNS_MAX_RDATA;
    if (rr->rdata_overflow && rr->rdata_overflow_len > 0 && rr->rdlength > rdlen) {
        rdlen = rr->rdata_overflow_len;
        rdata = rr->rdata_overflow;
    }
    if (write_u16(outp, remaining, rdlen)) return -1;
    if (write_bytes(outp, remaining, rdata, rdlen)) return -1;
    return 0;
}

static int edns_option_is_present(const dns_edns_option_t *opt) {
    return opt && (opt->present || opt->option_code || opt->option_length || opt->data_len);
}

static int reassemble_dns_opt_record(const dns_opt_record_t *opt, u8 **outp, u32 *remaining) {
    if (!opt || !outp || !remaining) return -1;
    uint16_t name_len = opt->name_len;
    if (name_len > DNS_MAX_NAME_LEN) name_len = DNS_MAX_NAME_LEN;
    if (write_dns_name(outp, remaining, opt->name, name_len)) return -1;
    uint16_t type = opt->type;
    if (write_u16(outp, remaining, type)) return -1;
    uint16_t cls = opt->udp_payload_size;
    if (write_u16(outp, remaining, cls)) return -1;
    uint32_t ttl = 0;
    ttl |= ((uint32_t)(opt->ext_rcode & 0xFF) << 24);
    ttl |= ((uint32_t)(opt->edns_version & 0xFF) << 16);
    ttl |= (uint32_t)(opt->edns_flags & 0xFFFF);
    if (write_u32(outp, remaining, ttl)) return -1;
    uint16_t rdlen = opt->rdata_len;
    uint16_t rdat_len = opt->rdata_len;
    if (opt->rdata_overflow && opt->rdata_overflow_len > 0 && opt->rdlength > rdat_len) {
        rdlen = opt->rdata_overflow_len;
        if (write_u16(outp, remaining, rdlen)) return -1;
        return write_bytes(outp, remaining, opt->rdata_overflow, rdlen);
    }
    if (opt->option_count) {
        uint32_t total = 0;
        for (uint16_t i = 0; i < opt->option_count && i < DNS_MAX_EDNS_OPTIONS; i++) {
            if (!edns_option_is_present(&opt->options[i])) continue;
            uint16_t len = opt->options[i].data_len;
            if (len > DNS_MAX_OPT_RDATA) len = DNS_MAX_OPT_RDATA;
            total += 4u + len;
        }
        if (total > DNS_MAX_OPT_RDATA) return -1;
        rdlen = (uint16_t)total;
    } else {
        if (rdat_len > DNS_MAX_OPT_RDATA) rdat_len = DNS_MAX_OPT_RDATA;
        if (rdlen > rdat_len) rdlen = rdat_len;
    }
    if (write_u16(outp, remaining, rdlen)) return -1;
    if (opt->option_count) {
        for (uint16_t i = 0; i < opt->option_count && i < DNS_MAX_EDNS_OPTIONS; i++) {
            if (!edns_option_is_present(&opt->options[i])) continue;
            uint16_t len = opt->options[i].data_len;
            if (len > DNS_MAX_OPT_RDATA) len = DNS_MAX_OPT_RDATA;
            if (write_u16(outp, remaining, opt->options[i].option_code)) return -1;
            if (write_u16(outp, remaining, len)) return -1;
            if (write_bytes(outp, remaining, opt->options[i].data, len)) return -1;
        }
    } else if (write_bytes(outp, remaining, opt->rdata, rdlen)) return -1;
    return 0;
}

static int dso_tlv_is_present(const dns_dso_tlv_t *tlv) {
    return tlv && (tlv->present || tlv->tlv_type || tlv->tlv_length || tlv->data_len);
}

static int reassemble_dns_dso_tlv(const dns_dso_tlv_t *tlv, u8 **outp, u32 *remaining) {
    if (!tlv || !outp || !remaining) return -1;
    uint16_t len = tlv->data_len;
    if (len > DNS_MAX_DSO_DATA) len = DNS_MAX_DSO_DATA;
    if (tlv->has_keepalive) len = 8;
    if (write_u16(outp, remaining, tlv->tlv_type)) return -1;
    if (write_u16(outp, remaining, len)) return -1;
    if (tlv->has_keepalive) {
        if (write_u32(outp, remaining, tlv->inactivity_timeout)) return -1;
        if (write_u32(outp, remaining, tlv->keepalive_interval)) return -1;
    } else if (write_bytes(outp, remaining, tlv->data, len)) return -1;
    return 0;
}

static int reassemble_dns_opaque_rdata(const dns_opaque_rdata_t *o, u8 **outp, u32 *remaining) {
    if (!o || !outp || !remaining) return -1;
    uint16_t rdlen = o->rdata_len;
    if (rdlen > DNS_MAX_RDATA) rdlen = DNS_MAX_RDATA;
    if (write_u16(outp, remaining, rdlen)) return -1;
    if (write_bytes(outp, remaining, o->rdata, rdlen)) return -1;
    return 0;
}

static int reassemble_dns_message(const dns_message_t *m, u8 **outp, u32 *remaining) {
    if (!m || !outp || !remaining) return -1;

    /* Preserve the exact wire representation for parser-originated messages.
     * This retains compression pointers, unknown RDATA and header bits that
     * are not represented by the bounded model. */
    if (m->wire_len > 0) {
        if (m->wire_len > *remaining) return -1;
        memcpy(*outp, m->wire, m->wire_len);
        *outp += m->wire_len;
        *remaining -= m->wire_len;
        return 0;
    }

    dns_header_t header = m->header;
    if (header.opcode == 6) {
        header.qdcount = 0;
        header.ancount = 0;
        header.nscount = 0;
        header.arcount = 0;
        if (reassemble_dns_header(&header, outp, remaining)) return -1;
        uint16_t count = m->dso_tlv_count;
        if (count > DNS_MAX_DSO_TLVS) count = DNS_MAX_DSO_TLVS;
        for (uint16_t i = 0; i < count; i++) {
            if (!dso_tlv_is_present(&m->dso_tlvs[i])) continue;
            if (reassemble_dns_dso_tlv(&m->dso_tlvs[i], outp, remaining)) return -1;
        }
        return write_bytes(outp, remaining, m->dso_tail.data, m->dso_tail.len);
    }
    header.qdcount = count_questions_to_write(m) + m->section_tails[0].count;
    header.ancount = count_rrs_to_write(m->answers, m->answer_count) + m->section_tails[1].count;
    header.nscount = count_rrs_to_write(m->authorities, m->authority_count) + m->section_tails[2].count;
    header.arcount = clamp_u16((uint32_t)count_rrs_to_write(m->additionals, m->additional_count) +
                               (opt_is_present(m) ? 1u : 0u) + m->section_tails[3].count);
    if (reassemble_dns_header(&header, outp, remaining)) return -1;

    uint16_t qcount = m->question_count;
    if (qcount > DNS_MAX_QUESTIONS) qcount = DNS_MAX_QUESTIONS;
    for (uint16_t i = 0; i < qcount; i++) {
        if (!question_is_present(&m->questions[i])) continue;
        if (reassemble_dns_question(&m->questions[i], outp, remaining)) return -1;
    }
    if (write_bytes(outp, remaining, m->section_tails[0].data, m->section_tails[0].len)) return -1;
    uint16_t ancount = m->answer_count;
    if (ancount > DNS_MAX_RRS) ancount = DNS_MAX_RRS;
    for (uint16_t i = 0; i < ancount; i++) {
        if (!rr_is_present(&m->answers[i])) continue;
        if (reassemble_dns_resource_record(&m->answers[i], outp, remaining)) return -1;
    }
    if (write_bytes(outp, remaining, m->section_tails[1].data, m->section_tails[1].len)) return -1;
    uint16_t nscount = m->authority_count;
    if (nscount > DNS_MAX_RRS) nscount = DNS_MAX_RRS;
    for (uint16_t i = 0; i < nscount; i++) {
        if (!rr_is_present(&m->authorities[i])) continue;
        if (reassemble_dns_resource_record(&m->authorities[i], outp, remaining)) return -1;
    }
    if (write_bytes(outp, remaining, m->section_tails[2].data, m->section_tails[2].len)) return -1;
    uint16_t arcount = m->additional_count;
    if (arcount > DNS_MAX_RRS) arcount = DNS_MAX_RRS;
    uint16_t opt_at = m->has_opt_position && m->opt_position <= arcount ? m->opt_position : arcount;
    for (uint16_t i = 0; i <= arcount; i++) {
        if (i == opt_at && opt_is_present(m)) {
            if (reassemble_dns_opt_record(&m->opt_rr, outp, remaining)) return -1;
        }
        if (i == arcount) break;
        if (!rr_is_present(&m->additionals[i])) continue;
        if (reassemble_dns_resource_record(&m->additionals[i], outp, remaining)) return -1;
    }
    return write_bytes(outp, remaining, m->section_tails[3].data, m->section_tails[3].len);
}

int reassemble_dns_msgs(const dns_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len) {
    if (!packets || !output_buf || !out_len) return -1;
    u32 remaining = *out_len;
    u8 *p = output_buf;
    for (u32 i = 0; i < num_packets; i++) {
        const dns_packet_t *pkt = &packets[i];
        if (!pkt) return -1;
        switch (pkt->type) {
            case DNS_MESSAGE: {
                if (reassemble_dns_message(&pkt->u.dns_message, &p, &remaining)) return -1;
                break;
            }
            case DNS_HEADER: {
                if (reassemble_dns_header(&pkt->u.dns_header, &p, &remaining)) return -1;
                break;
            }
            case DNS_QUESTION: {
                if (reassemble_dns_question(&pkt->u.dns_question, &p, &remaining)) return -1;
                break;
            }
            case DNS_RESOURCE_RECORD: {
                if (reassemble_dns_resource_record(&pkt->u.dns_rr, &p, &remaining)) return -1;
                break;
            }
            case DNS_OPT_RECORD: {
                if (reassemble_dns_opt_record(&pkt->u.dns_opt, &p, &remaining)) return -1;
                break;
            }
            case DNS_OPAQUE_RDATA: {
                if (reassemble_dns_opaque_rdata(&pkt->u.dns_opaque, &p, &remaining)) return -1;
                break;
            }
            default: {
                return -1;
            }
        }
    }
    *out_len = (u32)(p - output_buf);
    return 0;
}
