// File: ./llm/tls/tls_parser.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tls_packets.h"

typedef uint8_t u8;
typedef uint32_t u32;

typedef struct {
    const u8 *ptr;
    u32 len;
} slice_t;

static int be16_read(const u8 *p, uint16_t *out) {
    if (!p || !out) return 0;
    *out = (uint16_t)((p[0] << 8) | p[1]);
    return 1;
}

static u32 be24_to_u32(const u8 *p) {
    return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2];
}

static uint16_t rd16_be(const u8 *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static int parse_tls_extensions(const u8 *buf, u32 len, tls_client_hello_t *ch);
static int parse_tls_handshake_body_fields(uint8_t msg_type, const u8 *body, u32 body_len, tls_handshake_packet_t *pkt);
static void parse_tls_following_handshakes(const u8 *buf, u32 len, tls_handshake_packet_t *pkt);

static int read_record_header(const u8 *buf, u32 buf_len, tls_record_header_t *hdr) {
    if (buf_len < 5) return 0;
    hdr->type = buf[0];
    hdr->version.major = buf[1];
    hdr->version.minor = buf[2];
    uint16_t len;
    if (!be16_read(buf + 3, &len)) return 0;
    hdr->length = len;
    return 1;
}

static int parse_tls_client_hello_body(const u8 *body, u32 body_len, tls_client_hello_t *ch) {
    if (!body || !ch || body_len < 2 + 32 + 1 + 2 + 1) return 0;
    memset(ch, 0, sizeof(*ch));
    u32 off = 0;

    ch->client_version.major = body[off++];
    ch->client_version.minor = body[off++];
    memcpy(ch->random, body + off, 32);
    off += 32;

    if (off >= body_len) return 0;
    uint8_t sid_len = body[off++];
    if (sid_len > TLS_MAX_SESSION_ID_LEN) return 0;
    if (off + sid_len > body_len) return 0;
    ch->session_id_len = sid_len;
    if (sid_len) memcpy(ch->session_id, body + off, sid_len);
    off += sid_len;

    if (off + 2 > body_len) return 0;
    uint16_t cs_len = rd16_be(body + off);
    off += 2;
    /* A zero-length vector is repaired by fix_tls().  Keep the ClientHello
     * model alive so semantic mutation can explore the surrounding handshake
     * instead of immediately falling back to byte-level havoc. */
    if ((cs_len & 1u) || cs_len > TLS_MAX_CIPHER_SUITES_BYTES) return 0;
    if (off + cs_len > body_len) return 0;
    ch->cipher_suites_len = cs_len;
    memcpy(ch->cipher_suites, body + off, cs_len);
    off += cs_len;

    if (off >= body_len) return 0;
    uint8_t cm_len = body[off++];
    if (cm_len > TLS_MAX_COMPRESSION_METHODS) return 0;
    if (off + cm_len > body_len) return 0;
    ch->compression_methods_len = cm_len;
    memcpy(ch->compression_methods, body + off, cm_len);
    off += cm_len;

    if (off == body_len) {
        ch->extensions_len = 0;
        return 1;
    }
    if (off + 2 > body_len) return 0;
    uint16_t ext_len = rd16_be(body + off);
    off += 2;
    if (ext_len > TLS_MAX_EXTENSIONS_BYTES) return 0;
    if (off + ext_len != body_len) return 0;
    ch->extensions_present = 1;
    ch->extensions_len = ext_len;
    if (ext_len) memcpy(ch->extensions, body + off, ext_len);
    /* Preserve the raw extension vector even when the bounded structured
     * view cannot represent every item.  The fixer/reassembler can still
     * normalize the raw TLV vector. */
    if (ext_len && !parse_tls_extensions(body + off, ext_len, ch))
        ch->extension_count = 0;
    return 1;
}


static int parse_tls_extensions(const u8 *buf, u32 len, tls_client_hello_t *ch) {
    if (!ch) return 0;
    ch->extension_count = 0;
    u32 off = 0;
    while (off < len) {
        if (len - off < 4) return 0;
        uint16_t typ = rd16_be(buf + off);
        uint16_t elen = rd16_be(buf + off + 2);
        off += 4;
        if (elen > len - off) return 0;
        if (ch->extension_count >= TLS_MAX_EXTENSION_ITEMS || elen > TLS_MAX_EXTENSION_DATA_BYTES) return 0;
        tls_extension_t *e = &ch->extension_items[ch->extension_count++];
        memset(e, 0, sizeof(*e));
        e->extension_type = typ;
        e->extension_data_len = elen;
        if (elen) memcpy(e->extension_data, buf + off, elen);
        off += elen;
    }
    return off == len;
}


static void tls_copy_bytes(uint8_t *dst, uint32_t dst_cap, const uint8_t *src, uint32_t len, uint16_t *out_len) {
    uint32_t copy = len;
    if (copy > dst_cap) copy = dst_cap;
    if (copy && src) memcpy(dst, src, copy);
    if (out_len) *out_len = (uint16_t)copy;
}

static int parse_tls_certificate_body(const u8 *body, u32 body_len, tls_handshake_packet_t *pkt) {
    tls_certificate_body_t *c = &pkt->body.certificate;
    memset(c, 0, sizeof(*c));
    u32 off = 0;
    int tls13_layout = 0;
    if (body_len >= 4) {
        uint8_t ctx_len = body[0];
        if ((u32)ctx_len <= body_len - 4u) {
            u32 list_off = 1u + ctx_len;
            u32 list_len = be24_to_u32(body + list_off);
            if (list_len == body_len - list_off - 3u) tls13_layout = 1;
        }
    }
    if (tls13_layout) {
        c->tls13_layout = 1;
        uint8_t ctx_len = body[off++];
        c->request_context_len = ctx_len;
        if (ctx_len) memcpy(c->request_context, body + off, ctx_len);
        off += ctx_len;
    }
    if (body_len - off < 3) return 0;
    c->certificate_list_len = be24_to_u32(body + off);
    off += 3;
    if (c->certificate_list_len != body_len - off) return 0;
    u32 end = off + c->certificate_list_len;
    while (off < end && c->certificate_count < TLS_MAX_CERTIFICATE_ITEMS) {
        if (end - off < 3) return 0;
        u32 cert_len = be24_to_u32(body + off);
        off += 3;
        if (cert_len > end - off || cert_len > TLS_MAX_CERTIFICATE_BYTES) return 0;
        uint8_t idx = c->certificate_count++;
        c->certificate_len[idx] = cert_len;
        uint32_t copy = cert_len > TLS_MAX_CERTIFICATE_BYTES ? TLS_MAX_CERTIFICATE_BYTES : cert_len;
        if (copy) memcpy(c->certificate_bytes[idx], body + off, copy);
        off += cert_len;
        if (tls13_layout) {
            if (end - off < 2) return 0;
            uint16_t ext_len = rd16_be(body + off);
            c->certificate_extensions_len[idx] = ext_len;
            off += 2;
            if (ext_len > end - off || ext_len > TLS_MAX_CERTIFICATE_EXTENSION_BYTES) return 0;
            uint16_t ext_copy = ext_len > TLS_MAX_CERTIFICATE_EXTENSION_BYTES ? TLS_MAX_CERTIFICATE_EXTENSION_BYTES : ext_len;
            if (ext_copy) memcpy(c->certificate_extensions[idx], body + off, ext_copy);
            off += ext_len;
        }
    }
    return off == end;
}

static int parse_tls_handshake_body_fields(uint8_t msg_type, const u8 *body, u32 body_len, tls_handshake_packet_t *pkt) {
    if (!pkt) return 0;
    pkt->body_schema = TLS_HANDSHAKE_BODY_NONE;
    switch (msg_type) {
        case TLS_HANDSHAKE_CLIENT_HELLO:
            if (parse_tls_client_hello_body(body, body_len, &pkt->client_hello)) {
                pkt->has_client_hello = 1;
                pkt->body_schema = TLS_HANDSHAKE_BODY_CLIENT_HELLO;
                return 1;
            }
            return 0;
        case TLS_HANDSHAKE_CERTIFICATE:
            if (!parse_tls_certificate_body(body, body_len, pkt)) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_CERTIFICATE;
            return 1;
        case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: {
            if (body_len > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_CLIENT_KEY_EXCHANGE;
            tls_client_key_exchange_body_t *ck = &pkt->body.client_key_exchange;
            memset(ck, 0, sizeof(*ck));
            if (body_len >= 2) {
                uint16_t declared = rd16_be(body);
                if ((uint32_t)declared + 2u == body_len) {
                    ck->length_prefixed = 1;
                    tls_copy_bytes(ck->exchange, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body + 2, declared, &ck->exchange_len);
                    return 1;
                }
            }
            tls_copy_bytes(ck->exchange, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body, body_len, &ck->exchange_len);
            return 1;
        }
        case TLS_HANDSHAKE_CERTIFICATE_VERIFY: {
            if (body_len < 2 || body_len > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_CERTIFICATE_VERIFY;
            tls_certificate_verify_body_t *cv = &pkt->body.certificate_verify;
            memset(cv, 0, sizeof(*cv));
            cv->signature_scheme = rd16_be(body);
            if (body_len >= 4) {
                uint16_t slen = rd16_be(body + 2);
                if ((uint32_t)slen + 4u == body_len) { cv->length_prefixed = 1; tls_copy_bytes(cv->signature, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body + 4, slen, &cv->signature_len); }
                else tls_copy_bytes(cv->signature, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body + 2, body_len - 2, &cv->signature_len);
            } else {
                tls_copy_bytes(cv->signature, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body + 2, body_len - 2, &cv->signature_len);
            }
            return 1;
        }
        case TLS_HANDSHAKE_FINISHED:
            if (body_len > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_FINISHED;
            tls_copy_bytes(pkt->body.finished.verify_data, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body, body_len, &pkt->body.finished.verify_data_len);
            return 1;
        case TLS_HANDSHAKE_CERTIFICATE_URL:
            if (body_len < 3 || body_len - 3 > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_CERTIFICATE_URL;
            pkt->body.certificate_url.chain_type = body[0];
            pkt->body.certificate_url.url_and_hash_list_len = rd16_be(body + 1);
            if ((uint32_t)pkt->body.certificate_url.url_and_hash_list_len + 3u != body_len) return 0;
            tls_copy_bytes(pkt->body.certificate_url.url_and_hash_list, TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES, body + 3, pkt->body.certificate_url.url_and_hash_list_len, NULL);
            return 1;
        case TLS_HANDSHAKE_END_OF_EARLY_DATA:
            if (body_len != 0) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_END_OF_EARLY_DATA;
            return 1;
        case TLS_HANDSHAKE_KEY_UPDATE:
            if (body_len != 1) return 0;
            pkt->body_schema = TLS_HANDSHAKE_BODY_KEY_UPDATE;
            pkt->body.key_update.request_update = body[0];
            return 1;
        default:
            return 0;
    }
}

static void parse_tls_following_handshakes(const u8 *buf, u32 len, tls_handshake_packet_t *pkt) {
    if (!pkt) return;
    pkt->following_handshake_count = 0;
    u32 off = 0;
    while (off + 4 <= len && pkt->following_handshake_count < TLS_MAX_COALESCED_HANDSHAKES) {
        u32 hlen = be24_to_u32(buf + off + 1);
        if (hlen > len - off - 4u) break;
        tls_coalesced_handshake_t *h = &pkt->following[pkt->following_handshake_count++];
        h->msg_type = buf[off];
        h->length.b0 = buf[off + 1];
        h->length.b1 = buf[off + 2];
        h->length.b2 = buf[off + 3];
        h->wire = buf + off;
        h->wire_len = 4u + hlen;
        off += 4u + hlen;
    }
}

static int parse_tls_change_cipher_spec(const slice_t frag, tls_change_cipher_spec_packet_t *pkt) {
    if (frag.len != 1) return 0;
    pkt->ccs.type = frag.ptr[0];
    if (pkt->ccs.type != 1) return 0;
    return 1;
}

static int parse_tls_alert(const slice_t frag, tls_alert_packet_t *pkt) {
    if (frag.len != 2) return 0;
    pkt->alert.level = frag.ptr[0];
    pkt->alert.description = frag.ptr[1];
    return 1;
}

static int parse_tls_handshake(const slice_t frag, tls_handshake_packet_t *pkt) {
    pkt->fragment = frag.ptr;
    pkt->fragment_len = (uint16_t)frag.len;
    if (frag.len < 4) { pkt->is_fragment = 1; return 1; }
    pkt->handshake.msg_type = frag.ptr[0];
    pkt->handshake.length.b0 = frag.ptr[1];
    pkt->handshake.length.b1 = frag.ptr[2];
    pkt->handshake.length.b2 = frag.ptr[3];
    u32 decl = be24_to_u32(&frag.ptr[1]);
    if (decl > frag.len - 4) { pkt->is_fragment = 1; return 1; }
    pkt->following_handshakes = frag.ptr + 4 + decl;
    pkt->following_handshakes_len = (uint16_t)(frag.len - 4 - decl);
    pkt->handshake.body = (u8*)frag.ptr;
    pkt->handshake.body_len = (u32)frag.len;
    pkt->has_client_hello = 0;
    if (!parse_tls_handshake_body_fields(pkt->handshake.msg_type, frag.ptr + 4, decl, pkt)) {
        pkt->body_schema = TLS_HANDSHAKE_BODY_NONE;
        pkt->has_client_hello = 0;
    }
    if (pkt->following_handshakes_len) parse_tls_following_handshakes(pkt->following_handshakes, pkt->following_handshakes_len, pkt);
    return 1;
}

static int parse_tls_application_data(const slice_t frag, tls_application_data_packet_t *pkt) {
    pkt->app_data.data = (u8*)frag.ptr;
    if (frag.len > 0xFFFF) return 0;
    pkt->app_data.data_len = (uint16_t)frag.len;
    return 1;
}


/* Track framing across records without interpreting continuation bytes as a
 * new handshake header. This also handles a partial second handshake after a
 * complete first handshake in the same record. */
static void mark_tls_continuations(tls_packet_t *packets, u32 count) {
    uint8_t header[4];
    u32 header_bytes = 0, body_left = 0;
    for (u32 i = 0; i < count; i++) {
        if (packets[i].type != TLS_PACKET_HANDSHAKE) {
            header_bytes = body_left = 0;
            continue;
        }
        tls_handshake_packet_t *h = &packets[i].u.handshake;
        if (header_bytes || body_left) h->is_fragment = 1;
        u32 off = 0;
        while (off < h->fragment_len) {
            if (body_left) {
                u32 n = h->fragment_len - off;
                if (n > body_left) n = body_left;
                off += n; body_left -= n;
            } else {
                header[header_bytes++] = h->fragment[off++];
                if (header_bytes == 4) {
                    body_left = be24_to_u32(header + 1);
                    header_bytes = 0;
                }
            }
        }
    }
}

static void annotate_tls_handshake_fragments(tls_packet_t *packets, u32 count) {
    uint8_t assembled[18432u + 4u];
    for (u32 i = 0; i < count; i++) {
        if (packets[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_packet_t *h = &packets[i].u.handshake;
        if (!h->is_fragment || !h->fragment || h->fragment_len == 0) continue;
        u32 have = 0;
        u32 need = 0;
        u32 last = i, last_copy = 0;
        for (u32 j = i; j < count; j++) {
            if (packets[j].type != TLS_PACKET_HANDSHAKE) break;
            tls_handshake_packet_t *part = &packets[j].u.handshake;
            if (!part->fragment || part->fragment_len == 0) break;
            u32 copy = part->fragment_len;
            if (have + copy > sizeof(assembled)) copy = sizeof(assembled) - have;
            memcpy(assembled + have, part->fragment, copy);
            have += copy;
            last = j;
            last_copy = copy;
            if (have >= 4 && need == 0) {
                u32 decl = be24_to_u32(assembled + 1);
                need = 4u + decl;
                if (need > sizeof(assembled)) break;
            }
            if (need && have >= need) break;
            if (copy != part->fragment_len) break;
        }
        if (need && have >= need) {
            u32 decl = need - 4u;
            tls_handshake_packet_t tmp;
            memset(&tmp, 0, sizeof(tmp));
            tmp.record = packets[i].u.handshake.record;
            parse_tls_handshake_body_fields(assembled[0], assembled + 4, decl, &tmp);
            if (have > need) {
                tls_handshake_packet_t *tail = &packets[last].u.handshake;
                u32 tail_len = have - need;
                if (tail_len <= last_copy)
                    parse_tls_following_handshakes(tail->fragment + last_copy - tail_len, tail_len, &tmp);
            }
            for (u32 k = i; k <= last; k++) {
                packets[k].u.handshake.fragment_decoded = 1;
                packets[k].u.handshake.fragmented_body_schema = tmp.body_schema;
            }
            if (tmp.following_handshake_count) {
                packets[last].u.handshake.following_handshake_count = tmp.following_handshake_count;
                memcpy(packets[last].u.handshake.following, tmp.following, sizeof(tmp.following));
            }
        }
    }
}

size_t parse_tls_msg(const u8 *buf, u32 buf_len, tls_packet_t *out_packets, u32 max_count) {
    if (!buf || !out_packets || max_count == 0) return 0;
    u32 off = 0;
    u32 count = 0;
    while (off < buf_len && count < max_count) {
        tls_record_header_t hdr;
        if (!read_record_header(buf + off, buf_len - off, &hdr)) return 0;
        if (hdr.length > 18432) return 0;
        if (off > buf_len - 5) return 0;
        u32 remain = buf_len - off - 5;
        if (hdr.length > remain) return 0;
        const u8 *frag_ptr = buf + off + 5;
        slice_t frag = { frag_ptr, hdr.length };
        tls_packet_t *out = &out_packets[count];
        memset(out, 0, sizeof(*out));
        out->wire = buf + off;
        out->wire_len = 5U + hdr.length;
        out->type = TLS_PACKET_UNKNOWN;
        if (hdr.type == TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC) {
            out->type = TLS_PACKET_CHANGE_CIPHER_SPEC;
            out->u.change_cipher_spec.record = hdr;
            if (!parse_tls_change_cipher_spec(frag, &out->u.change_cipher_spec)) out->type = TLS_PACKET_UNKNOWN;
        } else if (hdr.type == TLS_CONTENTTYPE_ALERT) {
            out->type = TLS_PACKET_ALERT;
            out->u.alert.record = hdr;
            if (!parse_tls_alert(frag, &out->u.alert)) out->type = TLS_PACKET_UNKNOWN;
        } else if (hdr.type == TLS_CONTENTTYPE_HANDSHAKE) {
            out->type = TLS_PACKET_HANDSHAKE;
            out->u.handshake.record = hdr;
            if (!parse_tls_handshake(frag, &out->u.handshake)) return 0;
        } else if (hdr.type == TLS_CONTENTTYPE_APPLICATION_DATA) {
            out->type = TLS_PACKET_APPLICATION_DATA;
            out->u.application_data.record = hdr;
            if (!parse_tls_application_data(frag, &out->u.application_data)) return 0;
        }
        if (out->type == TLS_PACKET_UNKNOWN) {
            out->u.opaque_record.record = hdr;
            out->u.opaque_record.app_data.data = (u8 *)frag.ptr;
            out->u.opaque_record.app_data.data_len = (uint16_t)frag.len;
        }
        off += 5U + hdr.length;
        count++;
    }
    mark_tls_continuations(out_packets, count);
    annotate_tls_handshake_fragments(out_packets, count);
    return off == buf_len ? count : 0;
}
