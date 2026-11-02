#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tls_packets.h"

#define TLS_MAX_PLAINTEXT_FRAGMENT 16384U
#define TLS_MAX_HANDSHAKE_BODY_BYTES (TLS_MAX_PLAINTEXT_FRAGMENT - 4U)

static uint32_t tls_u24_to_u32(tls_uint24_t v) {
    return ((uint32_t)v.b0 << 16) | ((uint32_t)v.b1 << 8) | (uint32_t)v.b2;
}

static void tls_u32_to_u24(uint32_t x, tls_uint24_t *v) {
    if (!v) return;
    if (x > TLS_MAX_HANDSHAKE_BODY_BYTES) x = TLS_MAX_HANDSHAKE_BODY_BYTES;
    v->b0 = (uint8_t)((x >> 16) & 0xff);
    v->b1 = (uint8_t)((x >> 8) & 0xff);
    v->b2 = (uint8_t)(x & 0xff);
}

static void ensure_tls_version(tls_record_header_t *record);

static int tls_cipher_present(const tls_client_hello_t *ch, uint16_t suite) {
    if (!ch) return 0;
    uint16_t len = ch->cipher_suites_len;
    if (len > TLS_MAX_CIPHER_SUITES_BYTES) len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (len & 1u) len--;
    for (uint16_t i = 0; i + 1 < len; i = (uint16_t)(i + 2)) {
        uint16_t cur = (uint16_t)(((uint16_t)ch->cipher_suites[i] << 8) | ch->cipher_suites[i + 1]);
        if (cur == suite) return 1;
    }
    return 0;
}

static void tls_append_cipher_if_absent(tls_client_hello_t *ch, uint16_t suite) {
    if (!ch || tls_cipher_present(ch, suite)) return;
    uint16_t len = ch->cipher_suites_len;
    if (len > TLS_MAX_CIPHER_SUITES_BYTES) len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (len & 1u) len--;
    if ((uint32_t)len + 2u > TLS_MAX_CIPHER_SUITES_BYTES) return;
    ch->cipher_suites[len++] = (uint8_t)(suite >> 8);
    ch->cipher_suites[len++] = (uint8_t)suite;
    ch->cipher_suites_len = len;
}


static uint32_t tls_client_hello_body_len(const tls_client_hello_t *ch) {
    if (!ch) return 0;
    uint32_t sid_len = ch->session_id_len;
    if (sid_len > TLS_MAX_SESSION_ID_LEN) sid_len = TLS_MAX_SESSION_ID_LEN;
    uint32_t cs_len = ch->cipher_suites_len;
    if (cs_len > TLS_MAX_CIPHER_SUITES_BYTES) cs_len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (cs_len & 1u) cs_len--;
    uint32_t cm_len = ch->compression_methods_len;
    if (cm_len > TLS_MAX_COMPRESSION_METHODS) cm_len = TLS_MAX_COMPRESSION_METHODS;
    uint32_t ext_len = ch->extensions_len;
    if (ext_len > TLS_MAX_EXTENSIONS_BYTES) ext_len = TLS_MAX_EXTENSIONS_BYTES;
    return 2u + 32u + 1u + sid_len + 2u + cs_len + 1u + cm_len + ((ch->extensions_present || ext_len) ? 2u + ext_len : 0u);
}

static int tls_valid_alert_description(uint8_t d) {
    switch (d) {
        case TLS_ALERT_CLOSE_NOTIFY:
        case TLS_ALERT_UNEXPECTED_MESSAGE:
        case TLS_ALERT_BAD_RECORD_MAC:
        case TLS_ALERT_DECRYPTION_FAILED_RESERVED:
        case TLS_ALERT_RECORD_OVERFLOW:
        case TLS_ALERT_DECOMPRESSION_FAILURE:
        case TLS_ALERT_HANDSHAKE_FAILURE:
        case TLS_ALERT_NO_CERTIFICATE_RESERVED:
        case TLS_ALERT_BAD_CERTIFICATE:
        case TLS_ALERT_UNSUPPORTED_CERTIFICATE:
        case TLS_ALERT_CERTIFICATE_REVOKED:
        case TLS_ALERT_CERTIFICATE_EXPIRED:
        case TLS_ALERT_CERTIFICATE_UNKNOWN:
        case TLS_ALERT_ILLEGAL_PARAMETER:
        case TLS_ALERT_UNKNOWN_CA:
        case TLS_ALERT_ACCESS_DENIED:
        case TLS_ALERT_DECODE_ERROR:
        case TLS_ALERT_DECRYPT_ERROR:
        case TLS_ALERT_EXPORT_RESTRICTION_RESERVED:
        case TLS_ALERT_PROTOCOL_VERSION:
        case TLS_ALERT_INSUFFICIENT_SECURITY:
        case TLS_ALERT_INTERNAL_ERROR:
        case TLS_ALERT_USER_CANCELED:
        case TLS_ALERT_NO_RENEGOTIATION:
        case TLS_ALERT_MISSING_EXTENSION:
        case TLS_ALERT_UNSUPPORTED_EXTENSION:
        case TLS_ALERT_UNRECOGNIZED_NAME:
        case TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE:
        case TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE:
        case TLS_ALERT_UNKNOWN_PSK_IDENTITY:
        case TLS_ALERT_CERTIFICATE_REQUIRED:
        case TLS_ALERT_NO_APPLICATION_PROTOCOL:
            return 1;
        default:
            return 0;
    }
}

static int tls_valid_handshake_type(uint8_t t) {
    switch (t) {
        case TLS_HANDSHAKE_HELLO_REQUEST:
        case TLS_HANDSHAKE_CLIENT_HELLO:
        case TLS_HANDSHAKE_SERVER_HELLO:
        case TLS_HANDSHAKE_HELLO_VERIFY_REQUEST:
        case TLS_HANDSHAKE_NEW_SESSION_TICKET:
        case TLS_HANDSHAKE_END_OF_EARLY_DATA:
        case TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
        case TLS_HANDSHAKE_CERTIFICATE:
        case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
        case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
        case TLS_HANDSHAKE_SERVER_HELLO_DONE:
        case TLS_HANDSHAKE_CERTIFICATE_VERIFY:
        case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
        case TLS_HANDSHAKE_FINISHED:
        case TLS_HANDSHAKE_CERTIFICATE_URL:
        case TLS_HANDSHAKE_CERTIFICATE_STATUS:
        case TLS_HANDSHAKE_SUPPLEMENTAL_DATA:
        case TLS_HANDSHAKE_KEY_UPDATE:
        case TLS_HANDSHAKE_MESSAGE_HASH:
            return 1;
        default:
            return 0;
    }
}

// RFC 5246/6066 extension lists are vectors of Extension {type, length, data}.
static void fix_client_hello_extensions_vector(tls_client_hello_t *ch) {
    if (!ch) return;
    if (ch->extensions_len > TLS_MAX_EXTENSIONS_BYTES) ch->extensions_len = TLS_MAX_EXTENSIONS_BYTES;
    uint16_t limit = ch->extensions_len;
    uint16_t off = 0;
    while (off < limit) {
        if ((uint16_t)(limit - off) < 4) {
            limit = off;
            break;
        }
        uint16_t ext_len = (uint16_t)(((uint16_t)ch->extensions[off + 2] << 8) | ch->extensions[off + 3]);
        if ((uint32_t)off + 4u + ext_len > limit) {
            ext_len = (uint16_t)(limit - off - 4u);
            ch->extensions[off + 2] = (uint8_t)(ext_len >> 8);
            ch->extensions[off + 3] = (uint8_t)(ext_len & 0xff);
            limit = (uint16_t)(off + 4u + ext_len);
            break;
        }
        off = (uint16_t)(off + 4u + ext_len);
    }
    ch->extensions_len = limit;
}

static void fix_client_hello(tls_handshake_packet_t *p) {
    if (!p || !p->has_client_hello) return;
    tls_client_hello_t *ch = &p->client_hello;

    if (ch->client_version.major != 3) ch->client_version.major = 3;
    if (ch->client_version.minor < 1 || ch->client_version.minor > 3) ch->client_version.minor = 3;

    if (ch->session_id_len > TLS_MAX_SESSION_ID_LEN)
        ch->session_id_len = TLS_MAX_SESSION_ID_LEN;

    if (ch->cipher_suites_len > TLS_MAX_CIPHER_SUITES_BYTES)
        ch->cipher_suites_len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (ch->cipher_suites_len & 1u)
        ch->cipher_suites_len--;
    if (ch->cipher_suites_len < 2)
        ch->cipher_suites_len = 0;
    /* Preserve mutator-generated suite ordering, including TLS 1.3 suites.
     * Only add broadly accepted OpenSSL suites when the vector is empty or
     * lacks common choices; overwriting here destroys semantic profiles. */
    tls_append_cipher_if_absent(ch, 0x1301); /* TLS_AES_128_GCM_SHA256 */
    tls_append_cipher_if_absent(ch, 0x1302); /* TLS_AES_256_GCM_SHA384 */
    tls_append_cipher_if_absent(ch, 0x1303); /* TLS_CHACHA20_POLY1305_SHA256 */
    tls_append_cipher_if_absent(ch, 0xc02f); /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    tls_append_cipher_if_absent(ch, 0xc030); /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    tls_append_cipher_if_absent(ch, 0x009c); /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    tls_append_cipher_if_absent(ch, 0x002f); /* TLS_RSA_WITH_AES_128_CBC_SHA */

    if (ch->compression_methods_len > TLS_MAX_COMPRESSION_METHODS)
        ch->compression_methods_len = TLS_MAX_COMPRESSION_METHODS;
    if (ch->compression_methods_len == 0) {
        ch->compression_methods_len = 1;
        ch->compression_methods[0] = 0;
    } else {
        int has_null = 0;
        for (uint8_t i = 0; i < ch->compression_methods_len; i++) {
            if (ch->compression_methods[i] == 0) {
                has_null = 1;
                break;
            }
        }
        if (!has_null) ch->compression_methods[0] = 0;
    }

    fix_client_hello_extensions_vector(ch);

    p->handshake.msg_type = TLS_HANDSHAKE_CLIENT_HELLO;
    uint32_t body_len = tls_client_hello_body_len(ch);
    tls_u32_to_u24(body_len, &p->handshake.length);
    p->record.type = TLS_CONTENTTYPE_HANDSHAKE;
    ensure_tls_version(&p->record);
    p->record.length = (uint16_t)(4u + body_len + p->following_handshakes_len);
}

static void ensure_tls_version(tls_record_header_t *record) {
    if (!record) return;
    if (record->version.major != 3) record->version.major = 3;
    if (record->version.minor < 1 || record->version.minor > 3) record->version.minor = 3;
}

void fix_change_cipher_spec_type(tls_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;
    for (int i = 0; i < num_packets; ++i) {
        if (pkts[i].type != TLS_PACKET_CHANGE_CIPHER_SPEC) continue;
        pkts[i].u.change_cipher_spec.record.type = TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC;
        pkts[i].u.change_cipher_spec.record.length = 1;
        pkts[i].u.change_cipher_spec.ccs.type = 1;
        ensure_tls_version(&pkts[i].u.change_cipher_spec.record);
    }
}

void fix_alert_record(tls_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;
    for (int i = 0; i < num_packets; ++i) {
        if (pkts[i].type != TLS_PACKET_ALERT) continue;
        pkts[i].u.alert.record.type = TLS_CONTENTTYPE_ALERT;
        pkts[i].u.alert.record.length = 2;
        ensure_tls_version(&pkts[i].u.alert.record);
        if (pkts[i].u.alert.alert.level != TLS_ALERT_LEVEL_WARNING &&
            pkts[i].u.alert.alert.level != TLS_ALERT_LEVEL_FATAL) {
            pkts[i].u.alert.alert.level = TLS_ALERT_LEVEL_FATAL;
        }
        if (!tls_valid_alert_description(pkts[i].u.alert.alert.description)) {
            pkts[i].u.alert.alert.description = TLS_ALERT_DECODE_ERROR;
        }
    }
}

void fix_handshake_record(tls_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;
    for (int i = 0; i < num_packets; ++i) {
        if (pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_packet_t *p = &pkts[i].u.handshake;
        if (p->is_fragment) continue;
        if (p->has_client_hello) {
            fix_client_hello(p);
            continue;
        }
        p->record.type = TLS_CONTENTTYPE_HANDSHAKE;
        ensure_tls_version(&p->record);
        if (!tls_valid_handshake_type(p->handshake.msg_type))
            p->handshake.msg_type = TLS_HANDSHAKE_CLIENT_HELLO;
        uint32_t body_bytes = 0;
        if (p->handshake.body && p->handshake.body_len >= 4) {
            body_bytes = p->handshake.body_len - 4;
            if (body_bytes >= p->following_handshakes_len) body_bytes -= p->following_handshakes_len;
        } else {
            uint32_t decl = tls_u24_to_u32(p->handshake.length);
            if (decl > TLS_MAX_HANDSHAKE_BODY_BYTES) decl = TLS_MAX_HANDSHAKE_BODY_BYTES;
            uint8_t *body = (uint8_t *)calloc(4U + decl, 1);
            if (body) {
                body[0] = p->handshake.msg_type;
                p->handshake.body = body;
                p->handshake.body_len = 4U + decl;
                body_bytes = decl;
            }
        }
        if (body_bytes > TLS_MAX_HANDSHAKE_BODY_BYTES) {
            body_bytes = TLS_MAX_HANDSHAKE_BODY_BYTES;
            p->handshake.body_len = 4U + body_bytes;
        }
        tls_u32_to_u24(body_bytes, &p->handshake.length);
        if (p->handshake.body && p->handshake.body_len >= 4) {
            p->handshake.body[0] = p->handshake.msg_type;
            p->handshake.body[1] = p->handshake.length.b0;
            p->handshake.body[2] = p->handshake.length.b1;
            p->handshake.body[3] = p->handshake.length.b2;
        }
        p->record.length = (uint16_t)(4U + body_bytes + p->following_handshakes_len);
    }
}

void fix_application_data_record(tls_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;
    for (int i = 0; i < num_packets; ++i) {
        if (pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        tls_application_data_packet_t *p = &pkts[i].u.application_data;
        p->record.type = TLS_CONTENTTYPE_APPLICATION_DATA;
        ensure_tls_version(&p->record);
        if (p->app_data.data_len > TLS_MAX_PLAINTEXT_FRAGMENT) p->app_data.data_len = TLS_MAX_PLAINTEXT_FRAGMENT;
        if (!p->app_data.data && p->app_data.data_len > 0) {
            p->app_data.data = (uint8_t *)calloc(p->app_data.data_len, 1);
            if (!p->app_data.data) p->app_data.data_len = 0;
        }
        p->record.length = p->app_data.data_len;
    }
}

// [RFC5246-6.2.1] TLSPlaintext.fragment length must match the record length
// and stay within 2^14 bytes. The per-content fixers above enforce this shape.
void fix_RFC5246_6_2_1_record_length_bounds(tls_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;
    for (int i = 0; i < num_packets; ++i) {
        switch (pkts[i].type) {
            case TLS_PACKET_CHANGE_CIPHER_SPEC:
                if (pkts[i].u.change_cipher_spec.record.length > TLS_MAX_PLAINTEXT_FRAGMENT)
                    pkts[i].u.change_cipher_spec.record.length = TLS_MAX_PLAINTEXT_FRAGMENT;
                break;
            case TLS_PACKET_ALERT:
                if (pkts[i].u.alert.record.length > TLS_MAX_PLAINTEXT_FRAGMENT)
                    pkts[i].u.alert.record.length = TLS_MAX_PLAINTEXT_FRAGMENT;
                break;
            case TLS_PACKET_HANDSHAKE:
                if (pkts[i].u.handshake.record.length > TLS_MAX_PLAINTEXT_FRAGMENT)
                    pkts[i].u.handshake.record.length = TLS_MAX_PLAINTEXT_FRAGMENT;
                break;
            case TLS_PACKET_APPLICATION_DATA:
                if (pkts[i].u.application_data.record.length > TLS_MAX_PLAINTEXT_FRAGMENT)
                    pkts[i].u.application_data.record.length = TLS_MAX_PLAINTEXT_FRAGMENT;
                break;
            default:
                break;
        }
    }
}

// [RFC5246-7.4.1.2, RFC6066-3] ClientHello vector fields must have bounded,
// self-consistent lengths; extensions are type-length-value vectors.
void fix_RFC5246_7_4_1_2_client_hello_vectors(tls_packet_t *pkts, int num_packets) {
    if (!pkts || num_packets <= 0) return;
    for (int i = 0; i < num_packets; ++i)
        if (pkts[i].type == TLS_PACKET_HANDSHAKE && pkts[i].u.handshake.has_client_hello)
            fix_client_hello(&pkts[i].u.handshake);
}

void fix_tls(tls_packet_t *pkt, int num_packets) {
    fix_change_cipher_spec_type(pkt, num_packets);
    fix_alert_record(pkt, num_packets);
    fix_handshake_record(pkt, num_packets);
    fix_application_data_record(pkt, num_packets);
    fix_RFC5246_6_2_1_record_length_bounds(pkt, num_packets);
    fix_RFC5246_7_4_1_2_client_hello_vectors(pkt, num_packets);
}
