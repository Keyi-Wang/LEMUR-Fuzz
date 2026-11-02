// dns_parser.c
// Production-ready DNS parser for concatenated UDP messages per RFC 1035 and RFC 6891.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "dns_packets.h"

// Portable aliases if caller expects u8/u32
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef struct {
    const u8 *base;
    u32 len;
    u32 off;
} cursor_t;

static uint16_t rd16(const u8 *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const u8 *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]; }
static uint64_t rd48(const u8 *p) { return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) | ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 8) | (uint64_t)p[5]; }

static size_t parse_DNS_HEADER(const u8 *buf, u32 len, dns_header_t *out) {
    if (len < 12 || out == NULL) return 0;
    out->packet_type = DNS_HEADER;
    out->id = rd16(buf);
    uint16_t flags = rd16(buf + 2);
    out->qr = (flags >> 15) & 0x1;
    out->opcode = (flags >> 11) & 0xF;
    out->aa = (flags >> 10) & 0x1;
    out->tc = (flags >> 9) & 0x1;
    out->rd = (flags >> 8) & 0x1;
    out->ra = (flags >> 7) & 0x1;
    out->z  = (flags >> 4) & 0x7;
    out->rcode = flags & 0xF;
    out->qdcount = rd16(buf + 4);
    out->ancount = rd16(buf + 6);
    out->nscount = rd16(buf + 8);
    out->arcount = rd16(buf + 10);
    return 12;
}

// Compute the encoded length of a domain name starting at p within message base of len.
// This function does not expand compression; it only walks the current encoding to find its on-the-wire size.
static size_t encoded_name_len(const u8 *base, u32 len, u32 start_off) {
    u32 off = start_off;
    u32 steps = 0;
    while (off < len) {
        if (steps++ > DNS_MAX_LABELS) return 0;
        u8 lablen = base[off];
        if ((lablen & 0xC0) == 0xC0) {
            if (off + 1 >= len) return 0;
            off += 2;
            return off - start_off; // pointer terminates the name
        }
        off++;
        if (lablen == 0) {
            return off - start_off;
        }
        if (lablen > 63) return 0;
        if (off + lablen > len) return 0;
        off += lablen;
        if ((off - start_off) > DNS_MAX_NAME_LEN) return 0;
    }
    return 0;
}

static size_t parse_DNS_QUESTION(const u8 *base, u32 len, u32 start_off, dns_question_t *out) {
    if (!out) return 0;
    out->packet_type = DNS_QUESTION;
    out->present = 0;
    size_t nlen = encoded_name_len(base, len, start_off);
    if (nlen == 0) return 0;
    if (nlen > DNS_MAX_NAME_LEN) return 0;
    if (start_off + nlen + 4 > len) return 0;
    out->name_len = (uint16_t)nlen;
    memcpy(out->name, base + start_off, nlen);
    out->qtype = rd16(base + start_off + (u32)nlen);
    out->qclass = rd16(base + start_off + (u32)nlen + 2);
    out->present = 1;
    return nlen + 4;
}

static int rr_add_name(const u8 *base, u32 len, u32 start_off, dns_resource_record_t *out, u32 *consumed) {
    if (!out || out->name_count >= DNS_MAX_RDATA_NAMES) return 0;
    size_t nlen = encoded_name_len(base, len, start_off);
    if (nlen == 0 || nlen > DNS_MAX_NAME_LEN) return 0;
    out->names[out->name_count].len = (uint16_t)nlen;
    memcpy(out->names[out->name_count].wire, base + start_off, nlen);
    out->name_count++;
    if (consumed) *consumed = (u32)nlen;
    return 1;
}

static int rr_add_u16(dns_resource_record_t *out, uint16_t v) {
    if (!out || out->u16_count >= DNS_MAX_RDATA_U16S) return 0;
    out->u16_values[out->u16_count++] = v;
    return 1;
}

static int rr_add_u32(dns_resource_record_t *out, uint32_t v) {
    if (!out || out->u32_count >= DNS_MAX_RDATA_U32S) return 0;
    out->u32_values[out->u32_count++] = v;
    return 1;
}

static int rr_add_char_string(const u8 *rdata, u32 rdlen, u32 *off, dns_resource_record_t *out) {
    if (!out || !off || *off >= rdlen || out->string_count >= DNS_MAX_RDATA_STRINGS) return 0;
    uint8_t slen = rdata[*off];
    (*off)++;
    if (slen > rdlen - *off) return 0;
    out->strings[out->string_count].len = slen;
    if (slen) memcpy(out->strings[out->string_count].data, rdata + *off, slen);
    out->string_count++;
    *off += slen;
    return 1;
}

static void parse_rr_rdata_view(const u8 *base, u32 msg_len, u32 rdata_off, dns_resource_record_t *out) {
    if (!base || !out) return;
    out->rdata_schema = 0;
    out->address_len = 0;
    out->protocol = 0;
    out->bitmap_len = 0;
    out->name_count = 0;
    out->u16_count = 0;
    out->u32_count = 0;
    out->string_count = 0;
    out->has_tsig = 0;
    out->tsig_algorithm_name_len = 0;
    out->tsig_time_signed = 0;
    out->tsig_fudge = 0;
    out->tsig_mac_len = 0;
    out->tsig_original_id = 0;
    out->tsig_error = 0;
    out->tsig_other_len = 0;
    uint32_t rdlen = out->rdlength;
    const u8 *rdata = base + rdata_off;
    switch (out->type) {
        case 1:
            if (rdlen == 4) { out->rdata_schema = out->type; out->address_len = 4; memcpy(out->address, rdata, 4); }
            break;
        case 28:
            if (rdlen == 16) { out->rdata_schema = out->type; out->address_len = 16; memcpy(out->address, rdata, 16); }
            break;
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: {
            uint32_t n = 0;
            if (rr_add_name(base, msg_len, rdata_off, out, &n) && n == rdlen) out->rdata_schema = out->type;
            break;
        }
        case 6: {
            uint32_t off = rdata_off, n = 0;
            if (!rr_add_name(base, msg_len, off, out, &n)) break;
            off += n;
            if (!rr_add_name(base, msg_len, off, out, &n)) break;
            off += n;
            if (off + 20 != rdata_off + rdlen) break;
            for (int i = 0; i < 5; i++) { rr_add_u32(out, rd32(base + off)); off += 4; }
            out->rdata_schema = out->type;
            break;
        }
        case 11:
            if (rdlen >= 5) {
                out->rdata_schema = out->type;
                out->address_len = 4;
                memcpy(out->address, rdata, 4);
                out->protocol = rdata[4];
                out->bitmap_len = (uint16_t)(rdlen - 5);
            }
            break;
        case 13: {
            uint32_t off = 0;
            if (rr_add_char_string(rdata, rdlen, &off, out) &&
                rr_add_char_string(rdata, rdlen, &off, out) && off == rdlen)
                out->rdata_schema = out->type;
            break;
        }
        case 14: {
            uint32_t off = rdata_off, n = 0;
            if (!rr_add_name(base, msg_len, off, out, &n)) break;
            off += n;
            if (!rr_add_name(base, msg_len, off, out, &n)) break;
            off += n;
            if (off == rdata_off + rdlen) out->rdata_schema = out->type;
            break;
        }
        case 15: {
            if (rdlen < 3) break;
            uint32_t n = 0;
            rr_add_u16(out, rd16(rdata));
            if (rr_add_name(base, msg_len, rdata_off + 2, out, &n) && n + 2 == rdlen) out->rdata_schema = out->type;
            break;
        }
        case 16: {
            uint32_t off = 0;
            while (off < rdlen) if (!rr_add_char_string(rdata, rdlen, &off, out)) return;
            out->rdata_schema = out->type;
            break;
        }
        case 33: {
            if (rdlen < 7) break;
            uint32_t n = 0;
            rr_add_u16(out, rd16(rdata));
            rr_add_u16(out, rd16(rdata + 2));
            rr_add_u16(out, rd16(rdata + 4));
            if (rr_add_name(base, msg_len, rdata_off + 6, out, &n) && n + 6 == rdlen) out->rdata_schema = out->type;
            break;
        }
        case 250: {
            uint32_t off = rdata_off, n = 0;
            if (!rr_add_name(base, msg_len, off, out, &n)) break;
            out->tsig_algorithm_name_len = (uint16_t)n;
            memcpy(out->tsig_algorithm_name, base + off, n);
            off += n;
            if (rdata_off + rdlen < off || rdata_off + rdlen - off < 10) break;
            out->tsig_time_signed = rd48(base + off); off += 6;
            out->tsig_fudge = rd16(base + off); off += 2;
            uint16_t mac_len = rd16(base + off); off += 2;
            if (rdata_off + rdlen < off || mac_len > rdata_off + rdlen - off) break;
            out->tsig_mac_len = mac_len > DNS_MAX_TSIG_MAC ? DNS_MAX_TSIG_MAC : mac_len;
            if (out->tsig_mac_len) memcpy(out->tsig_mac, base + off, out->tsig_mac_len);
            off += mac_len;
            if (rdata_off + rdlen < off || rdata_off + rdlen - off < 6) break;
            out->tsig_original_id = rd16(base + off); off += 2;
            out->tsig_error = rd16(base + off); off += 2;
            uint16_t other_len = rd16(base + off); off += 2;
            if (rdata_off + rdlen < off || other_len > rdata_off + rdlen - off) break;
            out->tsig_other_len = other_len > DNS_MAX_TSIG_OTHER ? DNS_MAX_TSIG_OTHER : other_len;
            if (out->tsig_other_len) memcpy(out->tsig_other_data, base + off, out->tsig_other_len);
            off += other_len;
            if (off == rdata_off + rdlen) { out->has_tsig = 1; out->rdata_schema = out->type; }
            break;
        }
        default:
            break;
    }
}

static size_t parse_DNS_RESOURCE_RECORD(const u8 *base, u32 len, u32 start_off, dns_resource_record_t *out) {
    if (!out) return 0;
    out->packet_type = DNS_RESOURCE_RECORD;
    out->present = 0;
    size_t nlen = encoded_name_len(base, len, start_off);
    if (nlen == 0 || nlen > DNS_MAX_NAME_LEN) return 0;
    if (start_off + nlen + 10 > len) return 0;
    out->name_len = (uint16_t)nlen;
    memcpy(out->name, base + start_off, nlen);
    u32 pos = start_off + (u32)nlen;
    out->type = rd16(base + pos); pos += 2;
    out->class_code = rd16(base + pos); pos += 2;
    out->ttl = rd32(base + pos); pos += 4;
    out->rdlength = rd16(base + pos); pos += 2;
    if (pos + out->rdlength > len) return 0;
    u16 to_copy = out->rdlength;
    if (to_copy > DNS_MAX_RDATA) to_copy = DNS_MAX_RDATA;
    out->rdata_overflow = out->rdlength > to_copy ? base + pos : NULL;
    out->rdata_overflow_len = out->rdata_overflow ? out->rdlength : 0;
    out->rdata_len = to_copy;
    if (to_copy) memcpy(out->rdata, base + pos, to_copy);
    parse_rr_rdata_view(base, len, pos, out);
    out->present = 1;
    return (size_t)((pos - start_off) + out->rdlength);
}

static void parse_edns_options(dns_opt_record_t *out) {
    if (!out) return;
    out->option_count = 0;
    uint32_t off = 0;
    while (off < out->rdata_len) {
        if (out->rdata_len - off < 4) return;
        uint16_t code = rd16(out->rdata + off);
        uint16_t olen = rd16(out->rdata + off + 2);
        off += 4;
        if (olen > out->rdata_len - off) return;
        if (out->option_count == DNS_MAX_EDNS_OPTIONS) {
            out->option_count = 0; /* Preserve the complete opaque option vector. */
            return;
        }
        if (out->option_count < DNS_MAX_EDNS_OPTIONS) {
            dns_edns_option_t *opt = &out->options[out->option_count++];
            memset(opt, 0, sizeof(*opt));
            opt->option_code = code;
            opt->option_length = olen;
            opt->data_len = olen > DNS_MAX_OPT_RDATA ? DNS_MAX_OPT_RDATA : olen;
            if (opt->data_len) memcpy(opt->data, out->rdata + off, opt->data_len);
            opt->present = 1;
        }
        off += olen;
    }
}

static size_t parse_DNS_OPT_RECORD(const u8 *base, u32 len, u32 start_off, dns_opt_record_t *out) {
    if (!out) return 0;
    out->packet_type = DNS_OPT_RECORD;
    out->present = 0;
    size_t nlen = encoded_name_len(base, len, start_off);
    if (nlen == 0 || nlen > DNS_MAX_NAME_LEN) return 0;
    if (start_off + nlen + 10 > len) return 0;
    out->name_len = (uint16_t)nlen;
    memcpy(out->name, base + start_off, nlen);
    u32 pos = start_off + (u32)nlen;
    out->type = rd16(base + pos); pos += 2;
    out->udp_payload_size = rd16(base + pos); pos += 2;
    uint32_t ttl = rd32(base + pos); pos += 4;
    out->ext_rcode = (uint8_t)((ttl >> 24) & 0xFF);
    out->edns_version = (uint8_t)((ttl >> 16) & 0xFF);
    out->edns_flags = (uint16_t)(ttl & 0xFFFF);
    out->rdlength = rd16(base + pos); pos += 2;
    if (pos + out->rdlength > len) return 0;
    u16 to_copy = out->rdlength;
    if (to_copy > DNS_MAX_OPT_RDATA) to_copy = DNS_MAX_OPT_RDATA;
    out->rdata_overflow = out->rdlength > to_copy ? base + pos : NULL;
    out->rdata_overflow_len = out->rdata_overflow ? out->rdlength : 0;
    out->rdata_len = to_copy;
    if (to_copy) memcpy(out->rdata, base + pos, to_copy);
    if (!out->rdata_overflow) parse_edns_options(out);
    else out->option_count = 0;
    out->present = 1;
    return (size_t)((pos - start_off) + out->rdlength);
}

static int parse_DNS_DSO_TLVS(const u8 *buf, u32 len, u32 *off, dns_message_t *msg) {
    msg->dso_tlv_count = 0;
    while (*off < len) {
        if (len - *off < 4) return 0;
        uint16_t tlv_type = rd16(buf + *off);
        uint16_t tlv_len = rd16(buf + *off + 2);
        *off += 4;
        if (tlv_len > len - *off) return 0;
        if (msg->dso_tail.data || msg->dso_tlv_count >= DNS_MAX_DSO_TLVS || tlv_len > DNS_MAX_DSO_DATA) {
            if (!msg->dso_tail.data) msg->dso_tail.data = buf + *off - 4;
            msg->dso_tail.len += 4u + tlv_len;
            msg->dso_tail.count++;
            msg->capacity_exceeded = 1;
        } else if (msg->dso_tlv_count < DNS_MAX_DSO_TLVS) {
            dns_dso_tlv_t *tlv = &msg->dso_tlvs[msg->dso_tlv_count++];
            memset(tlv, 0, sizeof(*tlv));
            tlv->tlv_type = tlv_type;
            tlv->tlv_length = tlv_len;
            tlv->data_len = tlv_len > DNS_MAX_DSO_DATA ? DNS_MAX_DSO_DATA : tlv_len;
            if (tlv->data_len) memcpy(tlv->data, buf + *off, tlv->data_len);
            if (tlv_type == 1 && tlv_len == 8) {
                tlv->has_keepalive = 1;
                tlv->inactivity_timeout = rd32(buf + *off);
                tlv->keepalive_interval = rd32(buf + *off + 4);
            }
            tlv->present = 1;
            if (tlv->data_len != tlv->tlv_length) msg->capacity_exceeded = 1;
        } else {
            msg->capacity_exceeded = 1;
        }
        *off += tlv_len;
    }
    return *off == len;
}

static int walk_only_rr(const u8 *base, u32 len, u32 start_off, u32 *bytes) {
    size_t nlen = encoded_name_len(base, len, start_off);
    if (nlen == 0) return 0;
    u32 pos = start_off + (u32)nlen;
    if (pos + 10 > len) return 0;
    uint16_t rdlength = rd16(base + pos + 8);
    pos += 10;
    if (pos + rdlength > len) return 0;
    *bytes = (u32)(pos - start_off + rdlength);
    return 1;
}

static size_t parse_DNS_MESSAGE(const u8 *buf, u32 len, dns_message_t *msg) {
    if (len < 12 || msg == NULL) return 0;
    memset(msg, 0, sizeof(*msg));
    msg->packet_type = DNS_MESSAGE;
    size_t hdr = parse_DNS_HEADER(buf, len, &msg->header);
    if (hdr == 0) return 0;
    u32 off = (u32)hdr;

    if (msg->header.opcode == 6) {
        if (msg->header.qdcount || msg->header.ancount || msg->header.nscount || msg->header.arcount)
            msg->capacity_exceeded = 1;
        if (!parse_DNS_DSO_TLVS(buf, len, &off, msg)) return 0;
        msg->wire_len = (uint16_t)((off <= DNS_MAX_WIRE) ? off : DNS_MAX_WIRE);
        if (msg->wire_len) memcpy(msg->wire, buf, msg->wire_len);
        return off;
    }

    // Questions
    msg->question_count = 0;
    for (u32 i = 0; i < msg->header.qdcount; ++i) {
        if (i < DNS_MAX_QUESTIONS) {
            size_t qsz = parse_DNS_QUESTION(buf, len, off, &msg->questions[i]);
            if (qsz == 0) return 0;
            off += (u32)qsz;
            msg->questions[i].present = 1;
            msg->question_count++;
        } else {
            // Skip beyond capacity
            size_t nlen = encoded_name_len(buf, len, off);
            if (nlen == 0) return 0;
            if (off + nlen + 4 > len) return 0;
            dns_section_tail_t *tail = &msg->section_tails[0];
            if (!tail->data) tail->data = buf + off;
            tail->len += (u32)nlen + 4; tail->count++;
            off += (u32)nlen + 4;
        }
    }

    // Answers
    msg->answer_count = 0;
    for (u32 i = 0; i < msg->header.ancount; ++i) {
        if (i < DNS_MAX_RRS) {
            size_t rsz = parse_DNS_RESOURCE_RECORD(buf, len, off, &msg->answers[i]);
            if (rsz == 0) return 0;
            off += (u32)rsz;
            msg->answers[i].present = 1;
            msg->answer_count++;
        } else {
            u32 b = 0; if (!walk_only_rr(buf, len, off, &b)) return 0;
            dns_section_tail_t *tail = &msg->section_tails[1];
            if (!tail->data) tail->data = buf + off;
            tail->len += b; tail->count++; off += b;
        }
    }

    // Authorities
    msg->authority_count = 0;
    for (u32 i = 0; i < msg->header.nscount; ++i) {
        if (i < DNS_MAX_RRS) {
            size_t rsz = parse_DNS_RESOURCE_RECORD(buf, len, off, &msg->authorities[i]);
            if (rsz == 0) return 0;
            off += (u32)rsz;
            msg->authorities[i].present = 1;
            msg->authority_count++;
        } else {
            u32 b = 0; if (!walk_only_rr(buf, len, off, &b)) return 0;
            dns_section_tail_t *tail = &msg->section_tails[2];
            if (!tail->data) tail->data = buf + off;
            tail->len += b; tail->count++; off += b;
        }
    }

    // Additionals
    msg->additional_count = 0;
    msg->has_opt = 0;
    for (u32 i = 0; i < msg->header.arcount; ++i) {
        if (msg->additional_count >= DNS_MAX_RRS) {
            u32 b = 0;
            if (!walk_only_rr(buf, len, off, &b)) return 0;
            dns_section_tail_t *tail = &msg->section_tails[3];
            if (!tail->data) tail->data = buf + off;
            tail->len += b; tail->count++; off += b;
            continue;
        }
        // Peek type if possible to detect OPT
        size_t nlen = encoded_name_len(buf, len, off);
        if (nlen == 0) return 0;
        if (off + nlen + 2 > len) return 0;
        uint16_t t = rd16(buf + off + (u32)nlen);
        if (t == 41) {
            // OPT RR
            dns_opt_record_t tmp;
            size_t osz = parse_DNS_OPT_RECORD(buf, len, off, &tmp);
            if (osz == 0) return 0;
            if (!msg->has_opt) {
                msg->opt_rr = tmp;
                msg->has_opt = 1;
                msg->has_opt_position = 1;
                msg->opt_position = msg->additional_count;
            }
            /* Keep OPT in the dedicated EDNS view only.  Older code also
             * mirrored it into additionals[], and reassembly then emitted both
             * the generic RR and opt_rr.  That broke parse->reassemble
             * metamorphism by growing one wire OPT into two OPT records. */
            off += (u32)osz;
        } else {
            if (msg->additional_count < DNS_MAX_RRS) {
                size_t rsz = parse_DNS_RESOURCE_RECORD(buf, len, off, &msg->additionals[msg->additional_count]);
                if (rsz == 0) return 0;
                off += (u32)rsz;
                msg->additionals[msg->additional_count].present = 1;
                msg->additional_count++;
            }
        }
    }

    /* Never silently claim a bounded projection is a complete message. */
    if (msg->header.qdcount != msg->question_count || msg->header.ancount != msg->answer_count ||
        msg->header.nscount != msg->authority_count ||
        msg->header.arcount != msg->additional_count + msg->has_opt) msg->capacity_exceeded = 1;
    dns_resource_record_t *sections[] = { msg->answers, msg->authorities, msg->additionals };
    uint16_t counts[] = { msg->answer_count, msg->authority_count, msg->additional_count };
    for (unsigned section=0; section<3; section++)
        for (uint16_t ri=0; ri<counts[section]; ri++)
            if (sections[section][ri].rdlength != sections[section][ri].rdata_len) msg->capacity_exceeded = 1;
    if (msg->has_opt && msg->opt_rr.rdlength != msg->opt_rr.rdata_len) msg->capacity_exceeded = 1;
    // Preserve wire
    msg->wire_len = (uint16_t)((off <= DNS_MAX_WIRE) ? off : DNS_MAX_WIRE);
    if (msg->wire_len) memcpy(msg->wire, buf, msg->wire_len);
    return off;
}

size_t parse_dns_msg(const u8 *buf, u32 buf_len, dns_packet_t *out_packets, u32 max_count) {
    if (!buf || buf_len == 0 || !out_packets || max_count == 0) return 0;
    cursor_t c = { buf, buf_len, 0 };
    u32 out_idx = 0;
    while (c.off < c.len && out_idx < max_count) {
        // Try to parse a message starting at current offset
        u32 remaining = c.len - c.off;
        dns_message_t tmp_msg;
        size_t mbytes = parse_DNS_MESSAGE(c.base + c.off, remaining, &tmp_msg);
        if (mbytes == 0) {
            // Parsing failed; stop to avoid infinite loop
            break;
        }
        out_packets[out_idx].type = DNS_MESSAGE;
        out_packets[out_idx].u.dns_message = tmp_msg;
        out_idx++;
        c.off += (u32)mbytes;
    }
    return c.off == c.len ? out_idx : 0;
}
