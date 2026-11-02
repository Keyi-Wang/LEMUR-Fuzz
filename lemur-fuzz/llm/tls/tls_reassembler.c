// File: ./llm/tls/tls_reassembler.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tls_packets.h"

typedef uint8_t u8;
typedef uint32_t u32;

static int write_be16(u8 *p, uint16_t v) {
    p[0] = (u8)((v >> 8) & 0xFF);
    p[1] = (u8)(v & 0xFF);
    return 1;
}

static int write_be24(u8 *p, uint32_t v) {
    p[0] = (u8)((v >> 16) & 0xFF);
    p[1] = (u8)((v >> 8) & 0xFF);
    p[2] = (u8)(v & 0xFF);
    return 1;
}


static u32 client_hello_extensions_len(const tls_client_hello_t *ch) {
    if (!ch || ch->extension_count == 0) {
        u32 ext_len = ch ? ch->extensions_len : 0;
        return ext_len > TLS_MAX_EXTENSIONS_BYTES ? TLS_MAX_EXTENSIONS_BYTES : ext_len;
    }
    u32 total = 0;
    for (u32 i = 0; i < ch->extension_count && i < TLS_MAX_EXTENSION_ITEMS; i++) {
        u32 len = ch->extension_items[i].extension_data_len;
        if (len > TLS_MAX_EXTENSION_DATA_BYTES) len = TLS_MAX_EXTENSION_DATA_BYTES;
        if (total + 4u + len > TLS_MAX_EXTENSIONS_BYTES) break;
        total += 4u + len;
    }
    return total;
}

static u32 client_hello_body_len(const tls_client_hello_t *ch) {
    if (!ch) return 0;
    u32 sid_len = ch->session_id_len;
    if (sid_len > TLS_MAX_SESSION_ID_LEN) sid_len = TLS_MAX_SESSION_ID_LEN;
    u32 cs_len = ch->cipher_suites_len;
    if (cs_len > TLS_MAX_CIPHER_SUITES_BYTES) cs_len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (cs_len & 1u) cs_len--;
    u32 cm_len = ch->compression_methods_len;
    if (cm_len > TLS_MAX_COMPRESSION_METHODS) cm_len = TLS_MAX_COMPRESSION_METHODS;
    u32 ext_len = client_hello_extensions_len(ch);
    return 2u + 32u + 1u + sid_len + 2u + cs_len + 1u + cm_len + ((ch->extensions_present || ext_len) ? 2u + ext_len : 0u);
}

static int write_client_hello_body(const tls_client_hello_t *ch, u8 *buf, u32 buf_cap, u32 *written) {
    if (!ch || !buf || !written) return 1;
    u32 need = client_hello_body_len(ch);
    if (buf_cap < need) return 2;
    u32 off = 0;
    buf[off++] = ch->client_version.major;
    buf[off++] = ch->client_version.minor;
    memcpy(buf + off, ch->random, 32);
    off += 32;

    u32 sid_len = ch->session_id_len;
    if (sid_len > TLS_MAX_SESSION_ID_LEN) sid_len = TLS_MAX_SESSION_ID_LEN;
    buf[off++] = (u8)sid_len;
    if (sid_len) memcpy(buf + off, ch->session_id, sid_len);
    off += sid_len;

    u32 cs_len = ch->cipher_suites_len;
    if (cs_len > TLS_MAX_CIPHER_SUITES_BYTES) cs_len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (cs_len & 1u) cs_len--;
    write_be16(buf + off, (uint16_t)cs_len);
    off += 2;
    if (cs_len) memcpy(buf + off, ch->cipher_suites, cs_len);
    off += cs_len;

    u32 cm_len = ch->compression_methods_len;
    if (cm_len > TLS_MAX_COMPRESSION_METHODS) cm_len = TLS_MAX_COMPRESSION_METHODS;
    buf[off++] = (u8)cm_len;
    if (cm_len) memcpy(buf + off, ch->compression_methods, cm_len);
    off += cm_len;

    u32 ext_len = client_hello_extensions_len(ch);
    if (ch->extensions_present || ext_len) {
        write_be16(buf + off, (uint16_t)ext_len);
        off += 2;
        if (ch->extension_count) {
            u32 wrote = 0;
            for (u32 i = 0; i < ch->extension_count && i < TLS_MAX_EXTENSION_ITEMS; i++) {
                u32 elen = ch->extension_items[i].extension_data_len;
                if (elen > TLS_MAX_EXTENSION_DATA_BYTES) elen = TLS_MAX_EXTENSION_DATA_BYTES;
                if (wrote + 4u + elen > ext_len) break;
                write_be16(buf + off, ch->extension_items[i].extension_type);
                write_be16(buf + off + 2, (uint16_t)elen);
                off += 4;
                if (elen) memcpy(buf + off, ch->extension_items[i].extension_data, elen);
                off += elen;
                wrote += 4u + elen;
            }
        } else if (ext_len) {
            memcpy(buf + off, ch->extensions, ext_len);
            off += ext_len;
        }
    }

    *written = off;
    return 0;
}


static u32 tls_typed_body_len(const tls_handshake_packet_t *pkt) {
    if (!pkt) return 0;
    switch (pkt->body_schema) {
        case TLS_HANDSHAKE_BODY_CERTIFICATE: {
            const tls_certificate_body_t *c = &pkt->body.certificate;
            u32 rctx_len = c->request_context_len;
            if (rctx_len > sizeof(c->request_context)) rctx_len = sizeof(c->request_context);
            u32 n = (c->tls13_layout ? 1u + rctx_len : 0u) + 3u;
            for (u32 i = 0; i < c->certificate_count && i < TLS_MAX_CERTIFICATE_ITEMS; i++) {
                u32 cert_len = c->certificate_len[i];
                if (cert_len > TLS_MAX_CERTIFICATE_BYTES) cert_len = TLS_MAX_CERTIFICATE_BYTES;
                u32 ext_len = c->certificate_extensions_len[i];
                if (ext_len > TLS_MAX_CERTIFICATE_EXTENSION_BYTES) ext_len = TLS_MAX_CERTIFICATE_EXTENSION_BYTES;
                n += 3u + cert_len + (c->tls13_layout ? 2u + ext_len : 0u);
            }
            return n;
        }
        case TLS_HANDSHAKE_BODY_CLIENT_KEY_EXCHANGE:
            { u32 n = pkt->body.client_key_exchange.exchange_len;
              if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
              return (pkt->body.client_key_exchange.length_prefixed ? 2u : 0u) + n; }
        case TLS_HANDSHAKE_BODY_CERTIFICATE_VERIFY:
            { u32 n = pkt->body.certificate_verify.signature_len;
              if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
              return 2u + (pkt->body.certificate_verify.length_prefixed ? 2u : 0u) + n; }
        case TLS_HANDSHAKE_BODY_FINISHED:
            { u32 n = pkt->body.finished.verify_data_len;
              return n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES ? TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES : n; }
        case TLS_HANDSHAKE_BODY_CERTIFICATE_URL:
            { u32 n = pkt->body.certificate_url.url_and_hash_list_len;
              if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
              return 3u + n; }
        case TLS_HANDSHAKE_BODY_END_OF_EARLY_DATA:
            return 0;
        case TLS_HANDSHAKE_BODY_KEY_UPDATE:
            return 1;
        default: /* GCOV_UNREACHABLE: body_schema is an enum set by parser/mutator constructors. */
            return 0; /* GCOV_UNREACHABLE */
    }
}

static int write_tls_typed_body(const tls_handshake_packet_t *pkt, u8 *buf, u32 cap, u32 *written) {
    if (!pkt || !buf || !written) return 1;
    u32 off = 0;
    switch (pkt->body_schema) {
        case TLS_HANDSHAKE_BODY_CERTIFICATE: {
            const tls_certificate_body_t *c = &pkt->body.certificate;
            if (c->tls13_layout) {
                u32 rctx_len = c->request_context_len;
                if (rctx_len > sizeof(c->request_context)) rctx_len = sizeof(c->request_context);
                if (off + 1u + rctx_len > cap) return 2;
                buf[off++] = (uint8_t)rctx_len;
                if (rctx_len) memcpy(buf + off, c->request_context, rctx_len);
                off += rctx_len;
            }
            u32 list_len = 0;
            for (u32 i = 0; i < c->certificate_count && i < TLS_MAX_CERTIFICATE_ITEMS; i++) {
                u32 cert_len = c->certificate_len[i];
                if (cert_len > TLS_MAX_CERTIFICATE_BYTES) cert_len = TLS_MAX_CERTIFICATE_BYTES;
                u32 ext_len = c->certificate_extensions_len[i];
                if (ext_len > TLS_MAX_CERTIFICATE_EXTENSION_BYTES) ext_len = TLS_MAX_CERTIFICATE_EXTENSION_BYTES;
                list_len += 3u + cert_len + (c->tls13_layout ? 2u + ext_len : 0u);
            }
            if (off + 3u + list_len > cap) return 2;
            write_be24(buf + off, list_len); off += 3;
            for (u32 i = 0; i < c->certificate_count && i < TLS_MAX_CERTIFICATE_ITEMS; i++) {
                u32 cert_len = c->certificate_len[i];
                if (cert_len > TLS_MAX_CERTIFICATE_BYTES) cert_len = TLS_MAX_CERTIFICATE_BYTES;
                write_be24(buf + off, cert_len); off += 3;
                if (cert_len) memcpy(buf + off, c->certificate_bytes[i], cert_len);
                off += cert_len;
                if (c->tls13_layout) {
                    u32 ext_len = c->certificate_extensions_len[i];
                    if (ext_len > TLS_MAX_CERTIFICATE_EXTENSION_BYTES) ext_len = TLS_MAX_CERTIFICATE_EXTENSION_BYTES;
                    write_be16(buf + off, (uint16_t)ext_len); off += 2;
                    if (ext_len) memcpy(buf + off, c->certificate_extensions[i], ext_len);
                    off += ext_len;
                }
            }
            break;
        }
        case TLS_HANDSHAKE_BODY_CLIENT_KEY_EXCHANGE: {
            const tls_client_key_exchange_body_t *ck = &pkt->body.client_key_exchange;
            u32 n = ck->exchange_len;
            if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
            if (ck->length_prefixed) { if (off + 2 > cap) return 2; write_be16(buf + off, (uint16_t)n); off += 2; }
            if (off + n > cap) return 2;
            if (n) memcpy(buf + off, ck->exchange, n);
            off += n;
            break;
        }
        case TLS_HANDSHAKE_BODY_CERTIFICATE_VERIFY: {
            const tls_certificate_verify_body_t *cv = &pkt->body.certificate_verify;
            u32 n = cv->signature_len;
            if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
            if (off + 2u + (cv->length_prefixed ? 2u : 0u) + n > cap) return 2;
            write_be16(buf + off, cv->signature_scheme); off += 2;
            if (cv->length_prefixed) { write_be16(buf + off, (uint16_t)n); off += 2; }
            if (n) memcpy(buf + off, cv->signature, n);
            off += n;
            break;
        }
        case TLS_HANDSHAKE_BODY_FINISHED: {
            u32 n = pkt->body.finished.verify_data_len;
            if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
            if (off + n > cap) return 2;
            if (n) memcpy(buf + off, pkt->body.finished.verify_data, n);
            off += n;
            break;
        }
        case TLS_HANDSHAKE_BODY_CERTIFICATE_URL: {
            u32 n = pkt->body.certificate_url.url_and_hash_list_len;
            if (n > TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) n = TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES;
            if (off + 3u + n > cap) return 2;
            buf[off++] = pkt->body.certificate_url.chain_type;
            write_be16(buf + off, (uint16_t)n); off += 2;
            if (n) memcpy(buf + off, pkt->body.certificate_url.url_and_hash_list, n);
            off += n;
            break;
        }
        case TLS_HANDSHAKE_BODY_END_OF_EARLY_DATA: /* GCOV_UNREACHABLE: zero-length typed body is emitted by the handshake header path. */
            break; /* GCOV_UNREACHABLE */
        case TLS_HANDSHAKE_BODY_KEY_UPDATE:
            if (off + 1 > cap) return 2;
            buf[off++] = pkt->body.key_update.request_update;
            break;
        default: /* GCOV_UNREACHABLE: body_schema is an enum set by parser/mutator constructors. */
            return 3; /* GCOV_UNREACHABLE */
    }
    *written = off;
    return 0;
}

static int reassemble_change_cipher_spec(const tls_change_cipher_spec_packet_t *pkt, u8 *buf, u32 buf_cap, u32 *written) {
    if (!pkt || !buf || !written) return 1;
    if (buf_cap < 6) return 2;
    buf[0] = (u8)pkt->record.type;
    buf[1] = pkt->record.version.major;
    buf[2] = pkt->record.version.minor;
    if (!write_be16(&buf[3], 1)) return 3;
    buf[5] = pkt->ccs.type;
    *written = 6;
    return 0;
}

static int reassemble_alert(const tls_alert_packet_t *pkt, u8 *buf, u32 buf_cap, u32 *written) {
    if (!pkt || !buf || !written) return 1;
    if (buf_cap < 7) return 2;
    buf[0] = (u8)pkt->record.type;
    buf[1] = pkt->record.version.major;
    buf[2] = pkt->record.version.minor;
    if (!write_be16(&buf[3], 2)) return 3;
    buf[5] = pkt->alert.level;
    buf[6] = pkt->alert.description;
    *written = 7;
    return 0;
}

static int reassemble_handshake(const tls_handshake_packet_t *pkt, u8 *buf, u32 buf_cap, u32 *written) {
    if (!pkt || !buf || !written) return 1;
    if (pkt->is_fragment) {
        if (!pkt->fragment || buf_cap < 5u + pkt->fragment_len) return 2;
        buf[0] = pkt->record.type; buf[1] = pkt->record.version.major; buf[2] = pkt->record.version.minor;
        write_be16(buf + 3, pkt->fragment_len);
        memcpy(buf + 5, pkt->fragment, pkt->fragment_len);
        *written = 5u + pkt->fragment_len;
        return 0;
    }
    if (pkt->has_client_hello && pkt->handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        u32 body_len = client_hello_body_len(&pkt->client_hello);
        u32 need = 5 + 4 + body_len + pkt->following_handshakes_len;
        if (buf_cap < need) return 2;
        buf[0] = TLS_CONTENTTYPE_HANDSHAKE;
        buf[1] = pkt->record.version.major;
        buf[2] = pkt->record.version.minor;
        if (!write_be16(&buf[3], (uint16_t)(need - 5))) return 3;
        buf[5] = TLS_HANDSHAKE_CLIENT_HELLO;
        write_be24(&buf[6], body_len);
        u32 wrote_body = 0;
        int rc = write_client_hello_body(&pkt->client_hello, &buf[9], buf_cap - 9, &wrote_body);
        if (rc != 0 || wrote_body != body_len) return rc ? rc : 4;
        if (pkt->following_handshakes_len && pkt->following_handshakes)
            memcpy(buf + 9 + body_len, pkt->following_handshakes, pkt->following_handshakes_len);
        *written = need;
        return 0;
    }
    u32 hs_decl = 0;
    if (pkt->body_schema && pkt->body_schema != TLS_HANDSHAKE_BODY_CLIENT_HELLO) {
        hs_decl = tls_typed_body_len(pkt);
    } else if (pkt->handshake.body && pkt->handshake.body_len >= 4) {
        hs_decl = pkt->handshake.body_len - 4u;
        if (pkt->following_handshakes_len && hs_decl >= pkt->following_handshakes_len)
            hs_decl -= pkt->following_handshakes_len;
    }
    u32 need = 5 + 4 + hs_decl + pkt->following_handshakes_len;
    if (buf_cap < need) return 2;
    buf[0] = (u8)pkt->record.type;
    buf[1] = pkt->record.version.major;
    buf[2] = pkt->record.version.minor;
    if (!write_be16(&buf[3], (uint16_t)(need - 5))) return 3;
    buf[5] = pkt->handshake.msg_type;
    write_be24(&buf[6], hs_decl);
    if (hs_decl) {
        if (pkt->body_schema && pkt->body_schema != TLS_HANDSHAKE_BODY_CLIENT_HELLO) {
            u32 wrote_body = 0;
            int rc = write_tls_typed_body(pkt, &buf[9], buf_cap - 9, &wrote_body);
            if (rc != 0 || wrote_body != hs_decl) return rc ? rc : 4;
        } else if (pkt->handshake.body && pkt->handshake.body_len >= 4 + hs_decl) {
            memcpy(&buf[9], pkt->handshake.body + 4, hs_decl);
        } else {
            memset(&buf[9], 0, hs_decl);
        }
    }
    if (pkt->following_handshakes_len && pkt->following_handshakes)
        memcpy(buf + 9 + hs_decl, pkt->following_handshakes, pkt->following_handshakes_len);
    *written = need;
    return 0;
}

static int reassemble_application_data(const tls_application_data_packet_t *pkt, u8 *buf, u32 buf_cap, u32 *written) {
    if (!pkt || !buf || !written) return 1;
    u32 len = pkt->app_data.data_len;
    u32 need = 5 + len;
    if (buf_cap < need) return 2;
    buf[0] = (u8)pkt->record.type;
    buf[1] = pkt->record.version.major;
    buf[2] = pkt->record.version.minor;
    if (!write_be16(&buf[3], (uint16_t)len)) return 3;
    if (len && pkt->app_data.data) {
        memcpy(&buf[5], pkt->app_data.data, len);
    } else if (len) {
        memset(&buf[5], 0, len);
    }
    *written = need;
    return 0;
}

int reassemble_tls_msgs(const tls_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len) {
    if (!packets || !output_buf || !out_len) return 1;
    u32 offset = 0;
    for (u32 i = 0; i < num_packets; ++i) {
        /* Semantic TLS mutations may intentionally truncate the encrypted tail
         * after ClientHello.  A TLS_PACKET_UNKNOWN with no wire and no opaque
         * bytes is the internal drop marker; it is not emitted on the wire. */
        if (packets[i].type == TLS_PACKET_UNKNOWN && !packets[i].wire && packets[i].wire_len == 0 &&
            packets[i].u.opaque_record.app_data.data_len == 0 && !packets[i].u.opaque_record.app_data.data) {
            continue;
        }
        if (packets[i].wire && packets[i].wire_len) {
            if (packets[i].wire_len > *out_len - offset) return 4;
            memcpy(output_buf + offset, packets[i].wire, packets[i].wire_len);
            offset += packets[i].wire_len;
            continue;
        }
        u32 wrote = 0;
        int rc = 1;
        if (offset > *out_len) return 4;
        switch (packets[i].type) {
            case TLS_PACKET_CHANGE_CIPHER_SPEC:
                rc = reassemble_change_cipher_spec(&packets[i].u.change_cipher_spec, output_buf + offset, *out_len - offset, &wrote);
                break;
            case TLS_PACKET_ALERT:
                rc = reassemble_alert(&packets[i].u.alert, output_buf + offset, *out_len - offset, &wrote);
                break;
            case TLS_PACKET_HANDSHAKE:
                rc = reassemble_handshake(&packets[i].u.handshake, output_buf + offset, *out_len - offset, &wrote);
                break;
            case TLS_PACKET_APPLICATION_DATA:
                rc = reassemble_application_data(&packets[i].u.application_data, output_buf + offset, *out_len - offset, &wrote);
                break;
            case TLS_PACKET_UNKNOWN:
                rc = reassemble_application_data(&packets[i].u.opaque_record, output_buf + offset, *out_len - offset, &wrote);
                break;
            default:
                return 2;
        }
        if (rc != 0) return rc;
        offset += wrote;
    }
    *out_len = offset;
    return 0;
}
