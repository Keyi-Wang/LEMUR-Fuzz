// File: ./llm/tls/tls_mutators.c
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "tls_packets.h"

typedef uint8_t u8;

static int tls_mut_seed_init = 0;
static void tls_mut_seed(void){ if(!tls_mut_seed_init){ srand((unsigned)time(NULL)); tls_mut_seed_init=1; } }

static u8 rnd8(void){ tls_mut_seed(); return (u8)(rand() & 0xFF); }
static int rnd(int n){ tls_mut_seed(); return n>0 ? rand()%n : 0; }

/* Keep the OpenSSL policy in one place so short pilots can tune it without
 * changing the mutation logic.  Defaults match the proven opt4 schedule;
 * pilots can override them through the environment without rebuilding. */
static int tls_policy_pct(const char *name, int fallback) {
    static int initialized = 0;
    static int profile_pct = 50;
    static int tail_drop_pct = 65;
    static int typed_pct = 0;
    if (!initialized) {
        const char *v = getenv("LEMUR_TLS_PROFILE_PCT");
        if (v) profile_pct = atoi(v);
        v = getenv("LEMUR_TLS_TAIL_DROP_PCT");
        if (v) tail_drop_pct = atoi(v);
        v = getenv("LEMUR_TLS_TYPED_PCT");
        if (v) typed_pct = atoi(v);
        if (profile_pct < 0) profile_pct = 0;
        if (profile_pct > 100) profile_pct = 100;
        if (tail_drop_pct < 0) tail_drop_pct = 0;
        if (tail_drop_pct > 100) tail_drop_pct = 100;
        if (typed_pct < 0) typed_pct = 0;
        if (typed_pct > 100) typed_pct = 100;
        initialized = 1;
    }
    if (name && strcmp(name, "profile") == 0) return profile_pct;
    if (name && strcmp(name, "tail") == 0) return tail_drop_pct;
    if (name && strcmp(name, "typed") == 0) return typed_pct;
    return fallback;
}


static tls_record_header_t *tls_record_for(tls_packet_t *pkt);
static uint32_t tls_client_hello_body_len_local(const tls_client_hello_t *ch) {
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

static void mutate_version_byte(u8 *b, int is_major){
    int choice = rnd(8);
    switch(choice){
        case 0: *b = (u8)(is_major ? 3 : 3); break;
        case 1: *b = (u8)(is_major ? 3 : 0); break;
        case 2: *b = (u8)(is_major ? 3 : 1); break;
        case 3: *b = (u8)(is_major ? 3 : 2); break;
        case 4: *b = (u8)(is_major ? 3 : 3); break;
        case 5: *b = (u8)(is_major ? 3 : 4); break;
        case 6: *b ^= (u8)(1u << rnd(8)); break;
        default: *b = rnd8(); break;
    }
}

static void mutate_record_version_major(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        tls_record_header_t *rh = tls_record_for(&pkts[i]);
        if (rh) mutate_version_byte(&rh->version.major, 1);
    }
}

static void mutate_record_version_minor(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        tls_record_header_t *rh = tls_record_for(&pkts[i]);
        if (rh) mutate_version_byte(&rh->version.minor, 0);
    }
}

// Alert packet mutators
static void mutate_alert_level(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_ALERT) continue;
        uint8_t *lvl = &pkts[i].u.alert.alert.level;
        int choice = rnd(12);
        switch(choice){
            case 0: *lvl = TLS_ALERT_LEVEL_WARNING; break; // Canonical
            case 1: *lvl = TLS_ALERT_LEVEL_FATAL; break;   // Canonical alt
            case 2: *lvl = 0; break;                      // Boundary low
            case 3: *lvl = 255; break;                    // Boundary high
            case 4: *lvl ^= (uint8_t)(1u << rnd(7)); break; // Bit flip
            case 5: *lvl = (rnd(10) < 8) ? TLS_ALERT_LEVEL_WARNING : TLS_ALERT_LEVEL_FATAL; break; // Allowed range bias
            case 6: *lvl = rnd8(); break;                 // Encoding-shape/random
            case 7: *lvl = (uint8_t)(1 + rnd(2)); break;  // 1 or 2 random
            case 8: *lvl = (uint8_t)(rnd(4)); break;      // small range
            case 9: *lvl = (uint8_t)(2 + rnd(10)); break; // near allowed
            default: *lvl = rnd8(); break;                // random mix
        }
    }
}

static void mutate_alert_description(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    static const uint8_t valid_descs[] = {
        TLS_ALERT_CLOSE_NOTIFY,
        TLS_ALERT_UNEXPECTED_MESSAGE,
        TLS_ALERT_BAD_RECORD_MAC,
        TLS_ALERT_RECORD_OVERFLOW,
        TLS_ALERT_DECOMPRESSION_FAILURE,
        TLS_ALERT_HANDSHAKE_FAILURE,
        TLS_ALERT_BAD_CERTIFICATE,
        TLS_ALERT_UNSUPPORTED_CERTIFICATE,
        TLS_ALERT_CERTIFICATE_REVOKED,
        TLS_ALERT_CERTIFICATE_EXPIRED,
        TLS_ALERT_CERTIFICATE_UNKNOWN,
        TLS_ALERT_ILLEGAL_PARAMETER,
        TLS_ALERT_UNKNOWN_CA,
        TLS_ALERT_ACCESS_DENIED,
        TLS_ALERT_DECODE_ERROR,
        TLS_ALERT_DECRYPT_ERROR,
        TLS_ALERT_PROTOCOL_VERSION,
        TLS_ALERT_INSUFFICIENT_SECURITY,
        TLS_ALERT_INTERNAL_ERROR,
        TLS_ALERT_USER_CANCELED,
        TLS_ALERT_NO_RENEGOTIATION,
        TLS_ALERT_MISSING_EXTENSION,
        TLS_ALERT_UNSUPPORTED_EXTENSION,
        TLS_ALERT_UNRECOGNIZED_NAME,
        TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE,
        TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE,
        TLS_ALERT_UNKNOWN_PSK_IDENTITY,
        TLS_ALERT_CERTIFICATE_REQUIRED,
        TLS_ALERT_NO_APPLICATION_PROTOCOL
    };
    size_t vd_count = sizeof(valid_descs)/sizeof(valid_descs[0]);
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_ALERT) continue;
        uint8_t *desc = &pkts[i].u.alert.alert.description;
        int choice = rnd(16);
        switch(choice){
            case 0: *desc = TLS_ALERT_CLOSE_NOTIFY; break; // Canonical
            case 1: *desc = valid_descs[rnd((int)vd_count)]; break; // Allowed enum
            case 2: *desc = 0; break;                     // Boundary low
            case 3: *desc = 255; break;                   // Boundary high
            case 4: *desc ^= (uint8_t)(1u << rnd(7)); break; // Bit flip
            case 5: *desc = (uint8_t)(10); break;         // unexpected_message
            case 6: *desc = (uint8_t)(20); break;         // bad_record_mac
            case 7: *desc = (uint8_t)(40); break;         // handshake_failure
            case 8: *desc = (uint8_t)(70); break;         // protocol_version
            case 9: *desc = (uint8_t)(71); break;         // insufficient_security
            case 10: *desc = (uint8_t)(80); break;        // internal_error
            case 11: *desc = (uint8_t)(90); break;        // user_canceled
            case 12: *desc = (uint8_t)(100); break;       // no_renegotiation
            case 13: *desc = rnd8(); break;               // Random
            case 14: *desc = (uint8_t)(valid_descs[rnd((int)vd_count)] + (rnd(2)?1:0)); break; // near-valid
            default: *desc = rnd8(); break;               // mix
        }
    }
}

#include <string.h>

static uint32_t u24_to_u32(tls_uint24_t v){ return ((uint32_t)v.b0<<16)|((uint32_t)v.b1<<8)|((uint32_t)v.b2); }
static void u32_to_u24(uint32_t x, tls_uint24_t *v){ if(!v) return; v->b0=(uint8_t)((x>>16)&0xFF); v->b1=(uint8_t)((x>>8)&0xFF); v->b2=(uint8_t)(x&0xFF); }

static int tls_clone_handshake_body(tls_handshake_msg_t *hs){
    if(!hs || !hs->body || hs->body_len == 0) return 1;
    uint8_t *nb = (uint8_t*)malloc(hs->body_len);
    if(!nb) return 0;
    memcpy(nb, hs->body, hs->body_len);
    hs->body = nb;
    return 1;
}

static int tls_resize_handshake_body(tls_handshake_msg_t *hs, uint32_t body_bytes){
    if(!hs) return 0;
    if(body_bytes > 18428) body_bytes = 18428;
    uint32_t new_len = 4 + body_bytes;
    uint8_t *nb = (uint8_t*)malloc(new_len ? new_len : 4);
    if(!nb) return 0;
    memset(nb, 0, new_len ? new_len : 4);
    nb[0] = hs->msg_type;
    u32_to_u24(body_bytes, &hs->length);
    nb[1] = hs->length.b0;
    nb[2] = hs->length.b1;
    nb[3] = hs->length.b2;
    if(hs->body && hs->body_len > 4 && body_bytes > 0){
        uint32_t old_body = hs->body_len - 4;
        uint32_t copy = old_body < body_bytes ? old_body : body_bytes;
        memcpy(nb + 4, hs->body + 4, copy);
    }
    hs->body = nb;
    hs->body_len = new_len;
    return 1;
}

static int tls_is_client_hello(tls_packet_t *pkt) {
    return pkt && pkt->type == TLS_PACKET_HANDSHAKE &&
           pkt->u.handshake.has_client_hello &&
           pkt->u.handshake.handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO;
}

/* A captured TLS transcript contains ciphertext bound to the ClientHello
 * through the negotiated traffic keys.  After changing ClientHello, that
 * suffix cannot be replayed without recomputing the TLS key schedule. */
static int tls_starts_protected_epoch(const tls_packet_t *pkt) {
    if (!pkt) return 0;
    if (pkt->type == TLS_PACKET_CHANGE_CIPHER_SPEC ||
        pkt->type == TLS_PACKET_APPLICATION_DATA) return 1;
    if (pkt->type == TLS_PACKET_UNKNOWN) {
        uint8_t type = pkt->u.opaque_record.record.type;
        /* TLS 1.2 encrypted alerts retain content type 21 but no longer have
         * the two-byte plaintext alert shape. */
        if (type == TLS_CONTENTTYPE_APPLICATION_DATA ||
            (type == TLS_CONTENTTYPE_ALERT &&
             pkt->u.opaque_record.app_data.data_len != 2)) return 1;
    }
    return 0;
}

static void tls_drop_encrypted_tail_after(tls_packet_t *pkts, int num_packets, int first_idx) {
    if (!pkts || first_idx < 0) return;
    int protected_epoch = 0;
    int termination_emitted = 0;
    for (int i = first_idx + 1; i < num_packets; i++) {
        if (!protected_epoch && tls_starts_protected_epoch(&pkts[i]))
            protected_epoch = 1;
        if (protected_epoch) {
            memset(&pkts[i], 0, sizeof(pkts[i]));
            if (!termination_emitted) {
                /* End the testcase immediately instead of making OpenSSL
                 * wait for a Finished message that cannot be recomputed. */
                pkts[i].type = TLS_PACKET_ALERT;
                pkts[i].u.alert.record.type = TLS_CONTENTTYPE_ALERT;
                pkts[i].u.alert.record.version.major = 3;
                pkts[i].u.alert.record.version.minor = 3;
                pkts[i].u.alert.record.length = 2;
                pkts[i].u.alert.alert.level = TLS_ALERT_LEVEL_FATAL;
                pkts[i].u.alert.alert.description = TLS_ALERT_DECODE_ERROR;
                termination_emitted = 1;
            } else {
                pkts[i].type = TLS_PACKET_UNKNOWN;
            }
        }
    }
}

static void mutate_client_hello_version(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        mutate_version_byte(&ch->client_version.major, 1);
        mutate_version_byte(&ch->client_version.minor, 0);
    }
}

static void mutate_client_hello_random(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        switch (rnd(5)) {
            case 0: memset(ch->random, 0, sizeof(ch->random)); break;
            case 1: memset(ch->random, 0xff, sizeof(ch->random)); break;
            case 2: ch->random[rnd(32)] ^= (uint8_t)(1u << rnd(8)); break;
            default:
                for (size_t k = 0; k < sizeof(ch->random); k++)
                    if (rnd(3) == 0) ch->random[k] = rnd8();
                break;
        }
    }
}

static void mutate_client_hello_session_id_len(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        switch (rnd(6)) {
            case 0: ch->session_id_len = 0; break;
            case 1: ch->session_id_len = TLS_MAX_SESSION_ID_LEN; break;
            case 2: if (ch->session_id_len < TLS_MAX_SESSION_ID_LEN) ch->session_id_len++; break;
            case 3: if (ch->session_id_len > 0) ch->session_id_len--; break;
            default: ch->session_id_len = (uint8_t)rnd(TLS_MAX_SESSION_ID_LEN + 1); break;
        }
    }
}

static void mutate_client_hello_session_id(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        if (ch->session_id_len == 0) ch->session_id_len = 1;
        if (ch->session_id_len > TLS_MAX_SESSION_ID_LEN) ch->session_id_len = TLS_MAX_SESSION_ID_LEN;
        for (uint8_t k = 0; k < ch->session_id_len; k++)
            if (rnd(2) == 0) ch->session_id[k] = rnd8();
    }
}

static void mutate_client_hello_cipher_suites_len(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        static const uint16_t lens[] = {2, 4, 6, 16, 32, 64, 128, 256, 512};
        ch->cipher_suites_len = lens[rnd((int)(sizeof(lens) / sizeof(lens[0])))];
    }
}

static void mutate_client_hello_cipher_suites(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    static const uint16_t suites[] = {
        0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xc02b, 0xc02c,
        0x009e, 0x009f, 0x003c, 0x003d, 0x002f, 0x0035, 0x00ff
    };
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        if (ch->cipher_suites_len < 2) ch->cipher_suites_len = 2;
        if (ch->cipher_suites_len > TLS_MAX_CIPHER_SUITES_BYTES) ch->cipher_suites_len = TLS_MAX_CIPHER_SUITES_BYTES;
        if (ch->cipher_suites_len & 1u) ch->cipher_suites_len--;
        uint16_t slots = (uint16_t)(ch->cipher_suites_len / 2);
        if (slots == 0) continue;
        switch (rnd(5)) {
            case 0:
                for (uint16_t s = 0; s < slots; s++) {
                    uint16_t v = suites[rnd((int)(sizeof(suites) / sizeof(suites[0])))];
                    ch->cipher_suites[2*s] = (uint8_t)(v >> 8);
                    ch->cipher_suites[2*s + 1] = (uint8_t)v;
                }
                break;
            case 1:
                ch->cipher_suites[0] = 0x00; ch->cipher_suites[1] = 0xff;
                break;
            default:
                ch->cipher_suites[rnd(ch->cipher_suites_len)] ^= (uint8_t)(1u << rnd(8));
                break;
        }
    }
}

static void mutate_client_hello_compression_methods_len(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        ch->compression_methods_len = (uint8_t)(1 + rnd(TLS_MAX_COMPRESSION_METHODS));
    }
}

static void mutate_client_hello_compression_methods(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        if (ch->compression_methods_len == 0) ch->compression_methods_len = 1;
        if (ch->compression_methods_len > TLS_MAX_COMPRESSION_METHODS)
            ch->compression_methods_len = TLS_MAX_COMPRESSION_METHODS;
        ch->compression_methods[0] = 0;
        for (uint8_t k = 1; k < ch->compression_methods_len; k++)
            ch->compression_methods[k] = rnd8();
    }
}

static void mutate_client_hello_extensions_len(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        static const uint16_t lens[] = {0, 4, 8, 16, 32, 64, 128, 256, 512, 1024};
        ch->extensions_len = lens[rnd((int)(sizeof(lens) / sizeof(lens[0])))];
        ch->extensions_present = ch->extensions_len ? 1 : 0;
        ch->extension_count = 0;
    }
}

static int tls_ext_append(tls_client_hello_t *ch, uint16_t ext_type,
                          const uint8_t *data, uint16_t data_len) {
    if (!ch) return 0;
    ch->extension_count = 0;
    ch->extensions_present = 1;
    uint32_t need = (uint32_t)ch->extensions_len + 4u + data_len;
    if (need > TLS_MAX_EXTENSIONS_BYTES) return 0;
    uint16_t off = ch->extensions_len;
    ch->extensions[off++] = (uint8_t)(ext_type >> 8);
    ch->extensions[off++] = (uint8_t)(ext_type & 0xff);
    ch->extensions[off++] = (uint8_t)(data_len >> 8);
    ch->extensions[off++] = (uint8_t)(data_len & 0xff);
    if (data_len && data) memcpy(ch->extensions + off, data, data_len);
    ch->extensions_len = (uint16_t)need;
    return 1;
}

static void tls_ext_profile_sni(tls_client_hello_t *ch, const char *name) {
    uint8_t body[256];
    size_t name_len = name ? strlen(name) : 0;
    if (!ch || !name_len || name_len > 240) return;
    uint16_t list_len = (uint16_t)(1u + 2u + name_len);
    uint16_t off = 0;
    body[off++] = (uint8_t)(list_len >> 8);
    body[off++] = (uint8_t)(list_len & 0xff);
    body[off++] = 0; /* host_name */
    body[off++] = (uint8_t)(name_len >> 8);
    body[off++] = (uint8_t)(name_len & 0xff);
    memcpy(body + off, name, name_len);
    off = (uint16_t)(off + name_len);
    tls_ext_append(ch, 0x0000, body, off);
}

static void tls_ext_profile_supported_groups(tls_client_hello_t *ch, int variant) {
    uint8_t body[64];
    static const uint16_t groups_modern[] = {0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101};
    static const uint16_t groups_ffdhe[] = {0x001d, 0x0017, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104};
    static const uint16_t groups_legacy[] = {0x0017, 0x0018, 0x0019, 0x0015, 0x0016};
    const uint16_t *groups = groups_modern;
    size_t count = sizeof(groups_modern) / sizeof(groups_modern[0]);
    if (variant == 2) { groups = groups_ffdhe; count = sizeof(groups_ffdhe) / sizeof(groups_ffdhe[0]); }
    else if (variant == 3) { groups = groups_legacy; count = sizeof(groups_legacy) / sizeof(groups_legacy[0]); }
    uint16_t off = 2;
    if (variant == 1) { body[off++] = 0x0a; body[off++] = 0x0a; }
    for (size_t i = 0; i < count && off + 2 <= sizeof(body); i++) {
        body[off++] = (uint8_t)(groups[i] >> 8);
        body[off++] = (uint8_t)(groups[i] & 0xff);
    }
    uint16_t list_len = (uint16_t)(off - 2u);
    body[0] = (uint8_t)(list_len >> 8);
    body[1] = (uint8_t)(list_len & 0xff);
    tls_ext_append(ch, 0x000a, body, off);
}

static void tls_ext_profile_ec_points(tls_client_hello_t *ch) {
    static const uint8_t body[] = {1, 0}; /* uncompressed */
    tls_ext_append(ch, 0x000b, body, sizeof(body));
}

static void tls_ext_profile_sigalgs(tls_client_hello_t *ch) {
    uint8_t body[64];
    static const uint16_t sigalgs[] = {
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
        0x0807, 0x0808, 0x0809, 0x080a, 0x080b,
        0x0401, 0x0501, 0x0601, 0x0201,
        0x0402, 0x0502, 0x0602, 0x0203
    };
    uint16_t off = 2;
    for (size_t i = 0; i < sizeof(sigalgs) / sizeof(sigalgs[0]) && off + 2 <= sizeof(body); i++) {
        body[off++] = (uint8_t)(sigalgs[i] >> 8);
        body[off++] = (uint8_t)(sigalgs[i] & 0xff);
    }
    uint16_t list_len = (uint16_t)(off - 2u);
    body[0] = (uint8_t)(list_len >> 8);
    body[1] = (uint8_t)(list_len & 0xff);
    tls_ext_append(ch, 0x000d, body, off);
}

static void tls_ext_profile_alpn(tls_client_hello_t *ch, int h2_first) {
    uint8_t body[64];
    uint16_t off = 2;
    if (h2_first) {
        body[off++] = 2; memcpy(body + off, "h2", 2); off += 2;
    }
    body[off++] = 8; memcpy(body + off, "http/1.1", 8); off += 8;
    if (!h2_first) {
        body[off++] = 2; memcpy(body + off, "h2", 2); off += 2;
    }
    uint16_t list_len = (uint16_t)(off - 2u);
    body[0] = (uint8_t)(list_len >> 8);
    body[1] = (uint8_t)(list_len & 0xff);
    tls_ext_append(ch, 0x0010, body, off);
}

static void tls_ext_profile_supported_versions(tls_client_hello_t *ch, int variant) {
    uint8_t body[10];
    uint16_t off = 1;
    if (variant == 1) {
        body[off++] = 0x03; body[off++] = 0x04;
        body[off++] = 0x03; body[off++] = 0x03;
    } else if (variant == 2) {
        body[off++] = 0x03; body[off++] = 0x04;
        body[off++] = 0x03; body[off++] = 0x03;
        body[off++] = 0x03; body[off++] = 0x02;
    } else {
        body[off++] = 0x03; body[off++] = 0x03;
        body[off++] = 0x03; body[off++] = 0x02;
        body[off++] = 0x03; body[off++] = 0x01;
    }
    body[0] = (uint8_t)(off - 1u);
    tls_ext_append(ch, 0x002b, body, off);
}

static void tls_ext_profile_session_ticket(tls_client_hello_t *ch) {
    tls_ext_append(ch, 0x0023, NULL, 0);
}

static void tls_ext_profile_encrypt_then_mac(tls_client_hello_t *ch) {
    tls_ext_append(ch, 0x0016, NULL, 0);
}

static void tls_ext_profile_extended_master_secret(tls_client_hello_t *ch) {
    tls_ext_append(ch, 0x0017, NULL, 0);
}

static void tls_ext_profile_psk_key_exchange_modes(tls_client_hello_t *ch) {
    static const uint8_t body[] = {1, 1}; /* vector length=1, psk_dhe_ke */
    tls_ext_append(ch, 0x002d, body, sizeof(body));
}

static void tls_ext_profile_key_share_x25519(tls_client_hello_t *ch, int variant) {
    uint8_t body[2 + 2 + 2 + 65];
    uint16_t off = 2;
    uint16_t group = (variant == 2) ? 0x0017 : 0x001d;
    uint16_t key_len = (variant == 2) ? 65 : 32;
    body[off++] = (uint8_t)(group >> 8); body[off++] = (uint8_t)group;
    body[off++] = (uint8_t)(key_len >> 8); body[off++] = (uint8_t)key_len;
    if (variant == 2) {
        /* NIST P-256 generator, encoded as a valid uncompressed point. */
        static const uint8_t p256_generator[65] = {
            0x04,
            0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,
            0xf2,0x77,0x03,0x7d,0x81,0x2e,0xb3,0x3a,0x0f,0x4a,0x13,0x94,0x5d,0x89,0x8c,0x29,0x06,
            0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
            0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
        };
        memcpy(body + off, p256_generator, sizeof(p256_generator));
        off = (uint16_t)(off + sizeof(p256_generator));
    } else {
        for (uint16_t i = 0; i < key_len; i++)
            body[off++] = (uint8_t)(0x11u + (uint8_t)(i * 7u) + (uint8_t)(variant * 13u));
    }
    uint16_t list_len = (uint16_t)(off - 2u);
    body[0] = (uint8_t)(list_len >> 8);
    body[1] = (uint8_t)(list_len & 0xff);
    tls_ext_append(ch, 0x0033, body, off);
}

static void tls_ext_profile_status_request(tls_client_hello_t *ch) {
    static const uint8_t body[] = {1, 0, 0, 0, 0}; /* OCSP, empty responder_id_list and request_extensions */
    tls_ext_append(ch, 0x0005, body, sizeof(body));
}

static void tls_ext_profile_renegotiation_info(tls_client_hello_t *ch) {
    static const uint8_t body[] = {0};
    tls_ext_append(ch, 0xff01, body, sizeof(body));
}

static void tls_ext_profile_max_fragment_length(tls_client_hello_t *ch, uint8_t code) {
    uint8_t body[] = { (uint8_t)(code ? code : 1) };
    tls_ext_append(ch, 0x0001, body, sizeof(body));
}

static void tls_ext_profile_padding(tls_client_hello_t *ch, uint16_t pad_len) {
    uint8_t body[64];
    if (pad_len > sizeof(body)) pad_len = sizeof(body);
    memset(body, 0, pad_len);
    tls_ext_append(ch, 0x0015, body, pad_len);
}

static void tls_ext_profile_heartbeat(tls_client_hello_t *ch) {
    static const uint8_t body[] = {1}; /* peer_allowed_to_send */
    tls_ext_append(ch, 0x000f, body, sizeof(body));
}

static void tls_set_client_hello_extensions_profile(tls_client_hello_t *ch, int profile) {
    if (!ch) return;
    memset(ch->extensions, 0, sizeof(ch->extensions));
    ch->extensions_len = 0;
    ch->extension_count = 0;
    ch->extensions_present = 1;
    switch (profile % 10) {
        case 0:
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_supported_groups(ch, 0);
            tls_ext_profile_session_ticket(ch);
            tls_ext_profile_encrypt_then_mac(ch);
            tls_ext_profile_extended_master_secret(ch);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_supported_versions(ch, 1);
            tls_ext_profile_psk_key_exchange_modes(ch);
            tls_ext_profile_key_share_x25519(ch, 0);
            break;
        case 1:
            tls_ext_profile_sni(ch, "localhost");
            tls_ext_profile_supported_groups(ch, 0);
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_session_ticket(ch);
            tls_ext_profile_encrypt_then_mac(ch);
            tls_ext_profile_extended_master_secret(ch);
            tls_ext_profile_renegotiation_info(ch);
            break;
        case 2:
            tls_ext_profile_sni(ch, "localhost");
            tls_ext_profile_supported_versions(ch, 1);
            tls_ext_profile_supported_groups(ch, 1);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_alpn(ch, 1);
            tls_ext_profile_psk_key_exchange_modes(ch);
            tls_ext_profile_key_share_x25519(ch, 1);
            tls_ext_profile_status_request(ch);
            break;
        case 3:
            tls_ext_profile_sni(ch, "example.com");
            tls_ext_profile_supported_groups(ch, 2);
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_supported_versions(ch, 2);
            tls_ext_profile_session_ticket(ch);
            tls_ext_profile_status_request(ch);
            tls_ext_profile_padding(ch, 16);
            break;
        case 4:
            tls_ext_profile_sni(ch, "127.0.0.1");
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_supported_groups(ch, 0);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_session_ticket(ch);
            tls_ext_profile_renegotiation_info(ch);
            break;
        case 5:
            tls_ext_profile_supported_groups(ch, 0);
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_extended_master_secret(ch);
            tls_ext_profile_encrypt_then_mac(ch);
            break;
        case 6:
            tls_ext_profile_sni(ch, "localhost");
            tls_ext_profile_supported_versions(ch, 1);
            tls_ext_profile_supported_groups(ch, 2);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_key_share_x25519(ch, 2);
            tls_ext_profile_psk_key_exchange_modes(ch);
            tls_ext_profile_padding(ch, 32);
            break;
        case 7:
            tls_ext_profile_sni(ch, "openssl.local");
            tls_ext_profile_supported_groups(ch, 3);
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_alpn(ch, 0);
            tls_ext_profile_max_fragment_length(ch, 2);
            tls_ext_profile_heartbeat(ch);
            break;
        case 8:
            tls_ext_profile_supported_versions(ch, 2);
            tls_ext_profile_supported_groups(ch, 1);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_key_share_x25519(ch, 0);
            tls_ext_profile_status_request(ch);
            tls_ext_profile_session_ticket(ch);
            tls_ext_profile_padding(ch, 48);
            break;
        default:
            tls_ext_profile_sni(ch, "example.org");
            tls_ext_profile_supported_groups(ch, 2);
            tls_ext_profile_ec_points(ch);
            tls_ext_profile_sigalgs(ch);
            tls_ext_profile_supported_versions(ch, 0);
            tls_ext_profile_session_ticket(ch);
            tls_ext_profile_renegotiation_info(ch);
            tls_ext_profile_max_fragment_length(ch, 1);
            break;
    }
}

static void mutate_client_hello_extensions(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (!tls_is_client_hello(&pkts[i])) continue;
        tls_client_hello_t *ch = &pkts[i].u.handshake.client_hello;
        if (ch->extensions_len > TLS_MAX_EXTENSIONS_BYTES)
            ch->extensions_len = TLS_MAX_EXTENSIONS_BYTES;
        if (ch->extensions_len == 0) {
            tls_set_client_hello_extensions_profile(ch, rnd(10));
            continue;
        }
        switch (rnd(8)) {
            case 0:
            case 1:
                tls_set_client_hello_extensions_profile(ch, rnd(10));
                break;
            case 2:
                ch->extension_count = 0;
                memset(ch->extensions, 0, ch->extensions_len);
                break;
            case 3:
                ch->extension_count = 0;
                ch->extensions_present = 1;
                if (ch->extensions_len >= 4) {
                    ch->extensions[0] = 0x00; ch->extensions[1] = 0x0a;
                    ch->extensions[2] = 0x00; ch->extensions[3] = 0x00;
                }
                break;
            case 4:
                tls_ext_profile_sni(ch, rnd(2) ? "localhost" : "example.com");
                break;
            case 5:
                tls_ext_profile_alpn(ch, rnd(2));
                break;
            case 6:
                tls_ext_profile_supported_versions(ch, rnd(2));
                break;
            default:
                ch->extension_count = 0;
                for (uint16_t k = 0; k < ch->extensions_len && k < 64; k++)
                    if (rnd(3) == 0) ch->extensions[k] ^= rnd8();
                break;
        }
    }
}


static void tls_finalize_client_hello_packet(tls_packet_t *pkt) {
    if (!tls_is_client_hello(pkt)) return;
    tls_handshake_packet_t *hp = &pkt->u.handshake;
    tls_client_hello_t *ch = &hp->client_hello;
    if (ch->cipher_suites_len > TLS_MAX_CIPHER_SUITES_BYTES)
        ch->cipher_suites_len = TLS_MAX_CIPHER_SUITES_BYTES;
    if (ch->cipher_suites_len & 1u) ch->cipher_suites_len--;
    if (ch->cipher_suites_len < 2) {
        ch->cipher_suites_len = 2;
        ch->cipher_suites[0] = 0x00; ch->cipher_suites[1] = 0x2f;
    }
    if (ch->compression_methods_len == 0 || ch->compression_methods_len > TLS_MAX_COMPRESSION_METHODS)
        ch->compression_methods_len = 1;
    ch->compression_methods[0] = 0;
    if (ch->extensions_len > TLS_MAX_EXTENSIONS_BYTES)
        ch->extensions_len = TLS_MAX_EXTENSIONS_BYTES;
    if (ch->extensions_len) ch->extensions_present = 1;
    hp->handshake.msg_type = TLS_HANDSHAKE_CLIENT_HELLO;
    uint32_t body_len = tls_client_hello_body_len_local(ch);
    u32_to_u24(body_len, &hp->handshake.length);
    hp->record.type = TLS_CONTENTTYPE_HANDSHAKE;
    hp->record.version.major = 3;
    if (hp->record.version.minor < 1 || hp->record.version.minor > 3) hp->record.version.minor = 3;
    hp->record.length = (uint16_t)(4u + body_len + hp->following_handshakes_len);
}

static int tls_choose_openssl_profile(void) {
    /* Bias toward OpenSSL/ProfuzzBench-compatible TLS 1.2/1.3 ClientHello
     * shapes.  Profiles 0, 1 and 5 preserve high-value extension/cipher
     * combinations seen to reach deeper OpenSSL paths; the others are kept
     * at lower probability for protocol diversity. */
    static const int weighted_profiles[] = {0, 0, 0, 0, 3, 3, 2, 1, 5, 4};
    return weighted_profiles[rnd((int)(sizeof(weighted_profiles) / sizeof(weighted_profiles[0])))];
}

static void tls_make_client_hello_profile(tls_packet_t *pkt, int profile) {
    if (!tls_is_client_hello(pkt)) return;
    tls_client_hello_t *ch = &pkt->u.handshake.client_hello;
    ch->client_version.major = 3;
    ch->client_version.minor = 3; /* TLS 1.3 ClientHello uses legacy_version 0x0303; supported_versions carries 0x0304. */
    if (ch->session_id_len > TLS_MAX_SESSION_ID_LEN) ch->session_id_len = 0;
    static const uint16_t suites12[] = {0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0x003c, 0x003d, 0x002f, 0x0035, 0x00ff};
    static const uint16_t suites13[] = {0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0x009c, 0x009d, 0x00ff};
    static const uint16_t suites_legacy[] = {0xc013, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035, 0x000a, 0x00ff};
    static const uint16_t suites_chacha[] = {0x1303, 0x1301, 0xcca9, 0xcca8, 0xc02f, 0xc02b, 0x009e, 0x00ff};
    const uint16_t *suites = suites12;
    size_t nsuites = sizeof(suites12)/sizeof(suites12[0]);
    switch (profile % 10) {
        case 0: case 2: case 6: case 8: suites = suites13; nsuites = sizeof(suites13)/sizeof(suites13[0]); break;
        case 3: case 9: suites = suites_chacha; nsuites = sizeof(suites_chacha)/sizeof(suites_chacha[0]); break;
        case 7: suites = suites_legacy; nsuites = sizeof(suites_legacy)/sizeof(suites_legacy[0]); break;
        default: break;
    }
    ch->cipher_suites_len = (uint16_t)(nsuites * 2u);
    for (size_t i = 0; i < nsuites && 2*i + 1 < TLS_MAX_CIPHER_SUITES_BYTES; ++i) {
        ch->cipher_suites[2*i] = (uint8_t)(suites[i] >> 8);
        ch->cipher_suites[2*i + 1] = (uint8_t)suites[i];
    }
    ch->compression_methods_len = 1;
    ch->compression_methods[0] = 0;
    tls_set_client_hello_extensions_profile(ch, profile);
    tls_finalize_client_hello_packet(pkt);
}

static void mutate_handshake_msg_type(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    static const uint8_t valid_types[] = {
        TLS_HANDSHAKE_HELLO_REQUEST,
        TLS_HANDSHAKE_CLIENT_HELLO,
        TLS_HANDSHAKE_SERVER_HELLO,
        TLS_HANDSHAKE_HELLO_VERIFY_REQUEST,
        TLS_HANDSHAKE_NEW_SESSION_TICKET,
        TLS_HANDSHAKE_END_OF_EARLY_DATA,
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS,
        TLS_HANDSHAKE_CERTIFICATE,
        TLS_HANDSHAKE_SERVER_KEY_EXCHANGE,
        TLS_HANDSHAKE_CERTIFICATE_REQUEST,
        TLS_HANDSHAKE_SERVER_HELLO_DONE,
        TLS_HANDSHAKE_CERTIFICATE_VERIFY,
        TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE,
        TLS_HANDSHAKE_FINISHED,
        TLS_HANDSHAKE_CERTIFICATE_URL,
        TLS_HANDSHAKE_CERTIFICATE_STATUS,
        TLS_HANDSHAKE_SUPPLEMENTAL_DATA,
        TLS_HANDSHAKE_KEY_UPDATE,
        TLS_HANDSHAKE_MESSAGE_HASH
    };
    size_t vt = sizeof(valid_types)/sizeof(valid_types[0]);
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        uint8_t *mt = &pkts[i].u.handshake.handshake.msg_type;
        int c = rnd(10);
        switch(c){
            case 0: *mt = TLS_HANDSHAKE_CLIENT_HELLO; break;
            case 1: *mt = TLS_HANDSHAKE_SERVER_HELLO; break;
            case 2: *mt = valid_types[rnd((int)vt)]; break;
            case 3: *mt = 0; break;
            case 4: *mt = 255; break;
            case 5: *mt ^= (uint8_t)(1u<<rnd(7)); break;
            case 6: *mt = rnd8(); break;
            case 7: *mt = valid_types[rnd((int)vt)]; break;
            case 8: *mt = (uint8_t)(TLS_HANDSHAKE_FINISHED); break;
            default: *mt = rnd8(); break;
        }
    }
}

static void mutate_handshake_length(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_msg_t *hs = &pkts[i].u.handshake.handshake;
        tls_uint24_t *L = &hs->length;
        uint32_t cur = u24_to_u32(*L);
        uint32_t body_bytes = 0;
        if(hs->body && hs->body_len >= 4)
            body_bytes = hs->body_len - 4;
        int c = rnd(12);
        uint32_t target = body_bytes;
        switch(c){
            case 0: target = body_bytes; break;
            case 1: target = 0; break;
            case 2: target = 1; break;
            case 3: target = 18428; break;
            case 4: target = body_bytes?body_bytes-1:0; break;
            case 5: target = body_bytes + 1; break;
            case 6: target = (cur ^ (1u << (rnd(14)))) % 18429; break;
            case 7: target = (uint32_t)rnd(1024); break;
            case 8: target = (uint32_t)rnd(4096); break;
            case 9: target = body_bytes + (uint32_t)rnd(256); break;
            default: target = (uint32_t)rnd(8192); break;
        }
        if(target > 18428) target = 18428;
        if(tls_resize_handshake_body(hs, target)){
            pkts[i].u.handshake.record.length = (uint16_t)(4 + target);
        }
    }
}

static void add_handshake_body(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        if(pkts[i].u.handshake.handshake.body && pkts[i].u.handshake.handshake.body_len>0) continue;
        uint32_t len = 4 + (uint32_t)(rnd(256));
        uint8_t *nb = (uint8_t*)malloc(len);
        if(!nb) continue;
        memset(nb, 0, len);
        nb[0] = pkts[i].u.handshake.handshake.msg_type;
        nb[1] = pkts[i].u.handshake.handshake.length.b0;
        nb[2] = pkts[i].u.handshake.handshake.length.b1;
        nb[3] = pkts[i].u.handshake.handshake.length.b2;
        for(uint32_t k=4;k<len;k++) nb[k] = rnd8();
        pkts[i].u.handshake.handshake.body = nb;
        pkts[i].u.handshake.handshake.body_len = len;
    }
}

static void delete_handshake_body(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        pkts[i].u.handshake.handshake.body = NULL;
        pkts[i].u.handshake.handshake.body_len = 0;
    }
}

static void mutate_handshake_body(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        uint8_t *b = pkts[i].u.handshake.handshake.body;
        uint32_t bl = pkts[i].u.handshake.handshake.body_len;
        int c = rnd(12);
        if(!b || bl==0){ add_handshake_body(pkts+i, 1); b = pkts[i].u.handshake.handshake.body; bl = pkts[i].u.handshake.handshake.body_len; }
        else { if(!tls_clone_handshake_body(&pkts[i].u.handshake.handshake)) continue; b = pkts[i].u.handshake.handshake.body; bl = pkts[i].u.handshake.handshake.body_len; }
        if(!b) continue;
        switch(c){
            case 0: for(uint32_t k=4;k<bl;k++) b[k]=0; break;
            case 1: if(bl>4) b[4] ^= 0xFF; break;
            case 2: for(uint32_t k=4;k<bl;k++) b[k]^=(uint8_t)(1u<<rnd(7)); break;
            case 3: for(uint32_t k=4;k<bl;k++) b[k]=rnd8(); break;
            case 4: if(bl>5){ memmove(b+5,b+4,bl-5); b[4]=0; } break;
            case 5: if(bl>4) { uint32_t nchg = rnd(8); for(uint32_t t=0;t<nchg && 4+t<bl;t++) b[4+t]=rnd8(); } break;
            case 6: {
                uint32_t add = rnd(16);
                uint8_t *nb = (uint8_t*)malloc(bl+add);
                if(nb){ memcpy(nb,b,bl); for(uint32_t k=0;k<add;k++) nb[bl+k]=rnd8(); pkts[i].u.handshake.handshake.body=nb; pkts[i].u.handshake.handshake.body_len=bl+add; }
            } break;
            case 7: if(bl>8){ pkts[i].u.handshake.handshake.body_len = bl - rnd((int)(bl-4)); } break;
            case 8: b[0] = pkts[i].u.handshake.handshake.msg_type; break;
            case 9: b[1]=pkts[i].u.handshake.handshake.length.b0; b[2]=pkts[i].u.handshake.handshake.length.b1; b[3]=pkts[i].u.handshake.handshake.length.b2; break;
            default: for(uint32_t k=4;k<bl;k++) b[k]^=rnd8(); break;
        }
        if(rnd(2)){
            uint32_t new_decl = (pkts[i].u.handshake.handshake.body_len>4)? pkts[i].u.handshake.handshake.body_len - 4 : 0;
            u32_to_u24(new_decl, &pkts[i].u.handshake.handshake.length);
            if(pkts[i].u.handshake.handshake.body){ pkts[i].u.handshake.handshake.body[1]=pkts[i].u.handshake.handshake.length.b0; pkts[i].u.handshake.handshake.body[2]=pkts[i].u.handshake.handshake.length.b1; pkts[i].u.handshake.handshake.body[3]=pkts[i].u.handshake.handshake.length.b2; }
        }
    }
}

// Application Data packet mutators
#include <string.h>

static void ensure_app_owned(tls_application_data_t *ad){
    if(!ad) return;
    if(ad->data && ad->data_len>0){
        uint8_t *nb = (uint8_t*)malloc(ad->data_len);
        if(nb){
            memcpy(nb, ad->data, ad->data_len);
            ad->data = nb;
        }
    } else if(ad->data==NULL && ad->data_len>0){
        ad->data = (uint8_t*)malloc(ad->data_len);
        if(ad->data){ memset(ad->data, 0, ad->data_len); }
    }
}

static void mutate_app_record_version_major(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        mutate_version_byte(&pkts[i].u.application_data.record.version.major, 1);
    }
}

static void mutate_app_record_version_minor(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        mutate_version_byte(&pkts[i].u.application_data.record.version.minor, 0);
    }
}

static void mutate_app_record_length(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        uint16_t *L = &pkts[i].u.application_data.record.length;
        uint16_t dlen = pkts[i].u.application_data.app_data.data_len;
        int c = rnd(12);
        switch(c){
            case 0: *L = dlen; break;
            case 1: *L = 0; break;
            case 2: *L = 1; break;
            case 3: *L = 16384; break;
            case 4: *L = 18432; break;
            case 5: *L = (uint16_t)(dlen ? dlen-1 : 0); break;
            case 6: *L = (uint16_t)(dlen + rnd(256)); break;
            case 7: *L ^= (uint16_t)(1u << rnd(15)); break;
            case 8: *L = (uint16_t)rnd(1<<16); break;
            case 9: *L = (uint16_t)(5 + rnd(1024)); break;
            default: *L = (uint16_t)rnd(20000); break;
        }
    }
}

static void add_app_data_data(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        tls_application_data_t *ad = &pkts[i].u.application_data.app_data;
        if(ad->data && ad->data_len) continue;
        uint16_t len = (uint16_t)(1 + rnd(256));
        ad->data = (uint8_t*)malloc(len);
        if(!ad->data){ ad->data_len = 0; continue; }
        for(uint16_t k=0;k<len;k++) ad->data[k]=rnd8();
        ad->data_len = len;
        pkts[i].u.application_data.record.length = len;
    }
}

static void delete_app_data_data(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        tls_application_data_t *ad = &pkts[i].u.application_data.app_data;
        ad->data = NULL;
        ad->data_len = 0;
        pkts[i].u.application_data.record.length = 0;
    }
}

static void repeat_app_data_data(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        tls_application_data_t *ad = &pkts[i].u.application_data.app_data;
        if(!ad->data || ad->data_len==0) continue;
        ensure_app_owned(ad);
        if(!ad->data || ad->data_len==0) continue;
        uint16_t reps = (uint16_t)(2 + rnd(3));
        uint32_t newlen = (uint32_t)ad->data_len * reps;
        if(newlen > 0xFFFF) newlen = 0xFFFF;
        uint8_t *nb = (uint8_t*)malloc(newlen);
        if(!nb) continue;
        uint32_t pos = 0;
        while(pos < newlen){
            uint32_t chunk = ad->data_len;
            if(pos + chunk > newlen) chunk = newlen - pos;
            memcpy(nb + pos, ad->data, chunk);
            pos += chunk;
        }
        ad->data = nb;
        ad->data_len = (uint16_t)newlen;
        pkts[i].u.application_data.record.length = (uint16_t)newlen;
    }
}

static void mutate_app_data_data(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        tls_application_data_t *ad = &pkts[i].u.application_data.app_data;
        ensure_app_owned(ad);
        int c = rnd(14);
        if(ad->data == NULL && ad->data_len==0){ add_app_data_data(pkts+i,1); }
        switch(c){
            case 0: if(ad->data && ad->data_len){ memset(ad->data, 0, ad->data_len); } break;
            case 1: if(ad->data && ad->data_len){ ad->data[0] ^= 0xFF; } break;
            case 2: if(ad->data && ad->data_len){ for(uint16_t k=0;k<ad->data_len;k++) ad->data[k]^=(uint8_t)(1u<<rnd(7)); } break;
            case 3: if(ad->data && ad->data_len){ for(uint16_t k=0;k<ad->data_len;k++) ad->data[k]=rnd8(); } break;
            case 4: repeat_app_data_data(pkts+i,1); break;
            case 5: if(ad->data && ad->data_len<0xFFFE){
                        uint16_t add = (uint16_t)(1 + rnd(32));
                        uint32_t newlen = ad->data_len + add;
                        if(newlen>0xFFFF) newlen=0xFFFF;
                        uint8_t *nb = (uint8_t*)malloc(newlen);
                        if(nb){ memcpy(nb, ad->data, ad->data_len); memset(nb+ad->data_len, 0, newlen - ad->data_len); ad->data = nb; ad->data_len = (uint16_t)newlen; pkts[i].u.application_data.record.length = (uint16_t)newlen; }
                    } break;
            case 6: if(ad->data && ad->data_len>0){ uint16_t cut = (uint16_t)rnd(ad->data_len); ad->data_len -= cut; pkts[i].u.application_data.record.length = ad->data_len; } break;
            case 7: if(ad->data && ad->data_len){ uint16_t prefix = (uint16_t)rnd(8); for(uint16_t k=0;k<prefix;k++){ ad->data[k%ad->data_len]^=rnd8(); } } break;
            case 8: if(ad->data && ad->data_len){ uint16_t suffix = (uint16_t)rnd(8); for(uint16_t k=0;k<suffix;k++){ ad->data[(ad->data_len-1 - (k%ad->data_len))]^=rnd8(); } } break;
            case 9: if(ad->data && ad->data_len){ for(uint16_t k=0;k<ad->data_len;k++){ if(rnd(10)<3) ad->data[k]=rnd8(); }} break;
            case 10: if(ad->data && ad->data_len){ for(uint16_t k=0;k<ad->data_len;k++){ if((k%4)==0) ad->data[k]^=0xAA; }} break;
            case 11: if(ad->data && ad->data_len){ for(uint16_t k=0;k<ad->data_len;k++){ if((k%8)==0) ad->data[k]^=0x55; }} break;
            default: break;
        }
    }
}

static void mutate_app_data_data_len(tls_packet_t *pkts, size_t n){
    if(!pkts) return;
    for(size_t i=0;i<n;i++){
        if(pkts[i].type != TLS_PACKET_APPLICATION_DATA) continue;
        tls_application_data_t *ad = &pkts[i].u.application_data.app_data;
        ensure_app_owned(ad);
        uint16_t cur = ad->data_len;
        int c = rnd(12);
        uint16_t target = cur;
        switch(c){
            case 0: target = cur; break;
            case 1: target = 0; break;
            case 2: target = 1; break;
            case 3: target = 16384; break;
            case 4: target = 18432; break;
            case 5: target = (uint16_t)(cur ? cur-1 : 0); break;
            case 6: target = (uint16_t)(cur + rnd(256)); break;
            case 7: target = (uint16_t)((ad->data_len ^ (uint16_t)(1u << rnd(14))) % 18433); break;
            case 8: target = (uint16_t)rnd(18433); break;
            default: target = (uint16_t)rnd(18433); break;
        }
        uint8_t *nb = NULL;
        if(target){
            nb = (uint8_t*)malloc(target);
            if(!nb) continue;
            memset(nb, 0, target);
            if(ad->data && cur){
                uint16_t copy = cur < target ? cur : target;
                memcpy(nb, ad->data, copy);
            }
        }
        ad->data = nb;
        ad->data_len = target;
        pkts[i].u.application_data.record.length = target;
    }
}


/* Field-level mutators generated from the component-generation Step 6 prompt for
 * TLS record/handshake meta-fields that were previously only mutated indirectly. */
static tls_record_header_t *tls_record_for(tls_packet_t *pkt) {
    if (!pkt) return NULL;
    switch (pkt->type) {
        case TLS_PACKET_CHANGE_CIPHER_SPEC: return &pkt->u.change_cipher_spec.record;
        case TLS_PACKET_ALERT: return &pkt->u.alert.record;
        case TLS_PACKET_HANDSHAKE: return &pkt->u.handshake.record;
        case TLS_PACKET_APPLICATION_DATA: return &pkt->u.application_data.record;
        default: return NULL;
    }
}

static uint16_t tls_observed_record_len(const tls_packet_t *pkt) {
    if (!pkt) return 0;
    switch (pkt->type) {
        case TLS_PACKET_CHANGE_CIPHER_SPEC: return 1;
        case TLS_PACKET_ALERT: return 2;
        case TLS_PACKET_HANDSHAKE:
            if (pkt->u.handshake.has_client_hello &&
                pkt->u.handshake.handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO) {
                return (uint16_t)(4u + tls_client_hello_body_len_local(&pkt->u.handshake.client_hello));
            }
            return (uint16_t)(4u + u24_to_u32(pkt->u.handshake.handshake.length));
        case TLS_PACKET_APPLICATION_DATA:
            return pkt->u.application_data.app_data.data_len;
        default:
            return 0;
    }
}

static void mutate_record_length(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    static const uint16_t boundaries[] = {0, 1, 2, 4, 5, 16, 255, 256, 1024, 16384, 18432, 0xffff};
    for (size_t i = 0; i < n; i++) {
        tls_record_header_t *rh = tls_record_for(&pkts[i]);
        if (!rh) continue;
        uint16_t observed = tls_observed_record_len(&pkts[i]);
        switch (rnd(10)) {
            case 0: rh->length = observed; break;
            case 1: rh->length = boundaries[rnd((int)(sizeof(boundaries) / sizeof(boundaries[0])))]; break;
            case 2: rh->length = (uint16_t)(observed ? observed - 1 : 0); break;
            case 3: rh->length = (uint16_t)(observed + 1); break;
            case 4: rh->length ^= (uint16_t)(1u << rnd(15)); break;
            default: rh->length = (uint16_t)rnd(18433); break;
        }
    }
}

static void tls_fill_default_client_hello(tls_client_hello_t *ch) {
    if (!ch) return;
    memset(ch, 0, sizeof(*ch));
    ch->client_version.major = 3;
    ch->client_version.minor = 3;
    for (size_t i = 0; i < sizeof(ch->random); i++) ch->random[i] = rnd8();
    ch->session_id_len = 0;
    static const uint8_t suites[] = {0xc0,0x2f, 0xc0,0x30, 0x00,0x9e, 0x00,0xff};
    ch->cipher_suites_len = sizeof(suites);
    memcpy(ch->cipher_suites, suites, sizeof(suites));
    ch->compression_methods_len = 1;
    ch->compression_methods[0] = 0;
    tls_set_client_hello_extensions_profile(ch, 0);
}

static void add_has_client_hello(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_packet_t *hp = &pkts[i].u.handshake;
        hp->has_client_hello = 1;
        hp->handshake.msg_type = TLS_HANDSHAKE_CLIENT_HELLO;
        hp->record.type = TLS_CONTENTTYPE_HANDSHAKE;
        if (!hp->record.version.major) hp->record.version.major = 3;
        if (!hp->record.version.minor) hp->record.version.minor = 3;
        tls_fill_default_client_hello(&hp->client_hello);
        uint32_t bl = tls_client_hello_body_len_local(&hp->client_hello);
        u32_to_u24(bl, &hp->handshake.length);
        hp->record.length = (uint16_t)(4u + bl);
    }
}

static void delete_has_client_hello(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_packet_t *hp = &pkts[i].u.handshake;
        hp->has_client_hello = 0;
        if (hp->handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO && (!hp->handshake.body || hp->handshake.body_len == 0)) {
            hp->handshake.msg_type = TLS_HANDSHAKE_FINISHED;
            tls_resize_handshake_body(&hp->handshake, 12);
        }
    }
}

static void mutate_has_client_hello(tls_packet_t *pkts, size_t n) {
    if (rnd(2)) add_has_client_hello(pkts, n);
    else delete_has_client_hello(pkts, n);
}

static void mutate_handshake_body_len(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    static const uint32_t body_sizes[] = {0, 1, 12, 32, 64, 128, 255, 512, 1024, 4096};
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_packet_t *hp = &pkts[i].u.handshake;
        if (hp->has_client_hello && hp->handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO) {
            switch (rnd(5)) {
                case 0: mutate_client_hello_session_id_len(pkts + i, 1); break;
                case 1: mutate_client_hello_cipher_suites_len(pkts + i, 1); break;
                case 2: mutate_client_hello_compression_methods_len(pkts + i, 1); break;
                default: mutate_client_hello_extensions_len(pkts + i, 1); break;
            }
            uint32_t bl = tls_client_hello_body_len_local(&hp->client_hello);
            u32_to_u24(bl, &hp->handshake.length);
            hp->record.length = (uint16_t)(4u + bl);
            continue;
        }
        uint32_t target = body_sizes[rnd((int)(sizeof(body_sizes) / sizeof(body_sizes[0])))];
        if (rnd(3) == 0) target = (uint32_t)rnd(8192);
        if (tls_resize_handshake_body(&hp->handshake, target)) hp->record.length = (uint16_t)(4u + target);
    }
}

static void mutate_handshake_length_b0(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == TLS_PACKET_HANDSHAKE) pkts[i].u.handshake.handshake.length.b0 = 0;
}
static void mutate_handshake_length_b1(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == TLS_PACKET_HANDSHAKE) pkts[i].u.handshake.handshake.length.b1 = rnd8();
}
static void mutate_handshake_length_b2(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) if (pkts[i].type == TLS_PACKET_HANDSHAKE) pkts[i].u.handshake.handshake.length.b2 = rnd8();
}



static void mutate_tls_typed_handshake_body(tls_packet_t *pkts, size_t n) {
    if (!pkts) return;
    for (size_t i = 0; i < n; i++) {
        if (pkts[i].type != TLS_PACKET_HANDSHAKE) continue;
        tls_handshake_packet_t *hp = &pkts[i].u.handshake;
        switch ((tls_handshake_body_schema_t)hp->body_schema) {
            case TLS_HANDSHAKE_BODY_CERTIFICATE: {
                tls_certificate_body_t *c = &hp->body.certificate;
                if (!c->certificate_count) c->certificate_count = 1;
                uint8_t idx = (uint8_t)rnd(c->certificate_count < TLS_MAX_CERTIFICATE_ITEMS ? c->certificate_count : TLS_MAX_CERTIFICATE_ITEMS);
                switch (rnd(7)) {
                    case 0: c->tls13_layout ^= 1u; break;
                    case 1: c->request_context_len = (uint8_t)rnd(16); for (uint8_t j = 0; j < c->request_context_len; j++) c->request_context[j] = rnd8(); break;
                    case 2: c->certificate_len[idx] = (uint32_t)rnd(128); for (uint32_t j = 0; j < c->certificate_len[idx] && j < TLS_MAX_CERTIFICATE_BYTES; j++) c->certificate_bytes[idx][j] = rnd8(); break;
                    case 3: if (c->certificate_len[idx] < TLS_MAX_CERTIFICATE_BYTES) c->certificate_bytes[idx][c->certificate_len[idx]++] = rnd8(); break;
                    case 4: if (c->certificate_len[idx]) c->certificate_bytes[idx][rnd((int)c->certificate_len[idx])] ^= rnd8(); break;
                    case 5: c->certificate_extensions_len[idx] = (uint16_t)rnd(32); for (uint16_t j = 0; j < c->certificate_extensions_len[idx] && j < TLS_MAX_CERTIFICATE_EXTENSION_BYTES; j++) c->certificate_extensions[idx][j] = rnd8(); c->tls13_layout = 1; break;
                    default: c->certificate_count = (uint8_t)(1 + rnd(3)); break;
                }
                hp->handshake.msg_type = TLS_HANDSHAKE_CERTIFICATE;
                hp->body_schema = TLS_HANDSHAKE_BODY_CERTIFICATE;
                break;
            }
            case TLS_HANDSHAKE_BODY_CLIENT_KEY_EXCHANGE: {
                tls_client_key_exchange_body_t *ck = &hp->body.client_key_exchange;
                ck->length_prefixed ^= (uint8_t)rnd(2);
                if (rnd(2) && ck->exchange_len < TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) ck->exchange[ck->exchange_len++] = rnd8();
                else if (ck->exchange_len) ck->exchange[rnd((int)ck->exchange_len)] ^= rnd8();
                hp->handshake.msg_type = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
                break;
            }
            case TLS_HANDSHAKE_BODY_CERTIFICATE_VERIFY: {
                tls_certificate_verify_body_t *cv = &hp->body.certificate_verify;
                static const uint16_t schemes[] = {0x0401,0x0501,0x0601,0x0403,0x0503,0x0804,0x0807};
                cv->signature_scheme = schemes[rnd((int)(sizeof(schemes)/sizeof(schemes[0])))];
                cv->length_prefixed = 1;
                if (rnd(2) && cv->signature_len < TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) cv->signature[cv->signature_len++] = rnd8();
                else if (cv->signature_len) cv->signature[rnd((int)cv->signature_len)] ^= rnd8();
                hp->handshake.msg_type = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
                break;
            }
            case TLS_HANDSHAKE_BODY_FINISHED: {
                tls_finished_body_t *f = &hp->body.finished;
                if (!f->verify_data_len) f->verify_data_len = 12;
                if (rnd(3) == 0) f->verify_data_len = (uint16_t)(12 + rnd(21));
                for (uint16_t j = 0; j < f->verify_data_len && j < TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES; j++) if (rnd(5) == 0) f->verify_data[j] ^= rnd8();
                hp->handshake.msg_type = TLS_HANDSHAKE_FINISHED;
                break;
            }
            case TLS_HANDSHAKE_BODY_CERTIFICATE_URL: {
                tls_certificate_url_body_t *cu = &hp->body.certificate_url;
                cu->chain_type = (uint8_t)(rnd(2) ? 0 : 1);
                if (cu->url_and_hash_list_len < TLS_MAX_TYPED_HANDSHAKE_BODY_BYTES) cu->url_and_hash_list[cu->url_and_hash_list_len++] = rnd8();
                hp->handshake.msg_type = TLS_HANDSHAKE_CERTIFICATE_URL;
                break;
            }
            case TLS_HANDSHAKE_BODY_END_OF_EARLY_DATA:
                hp->handshake.msg_type = TLS_HANDSHAKE_END_OF_EARLY_DATA;
                break;
            case TLS_HANDSHAKE_BODY_KEY_UPDATE:
                hp->body.key_update.request_update = (uint8_t)rnd(2);
                hp->handshake.msg_type = TLS_HANDSHAKE_KEY_UPDATE;
                break;
            default:
                mutate_handshake_body(pkts + i, 1);
                break;
        }
    }
}

void dispatch_tls_multiple_mutations(tls_packet_t *pkts, int num_packets, int rounds) {
    if (!pkts || num_packets <= 0) return;
    if (rounds <= 0) rounds = 1;

    int client_hello_idx[64];
    int client_hello_count = 0;
    for (int i = 0; i < num_packets && client_hello_count < (int)(sizeof(client_hello_idx)/sizeof(client_hello_idx[0])); i++) {
        if (tls_is_client_hello(&pkts[i])) client_hello_idx[client_hello_count++] = i;
    }
    if (client_hello_count == 0) return;

    for (int r = 0; r < rounds; ++r) {
        int chosen_idx = client_hello_idx[rnd(client_hello_count)];
        tls_packet_t *p = &pkts[chosen_idx];
        p->wire_len = 0;

        /* Prefer local mutations over a full profile replacement.  A profile
         * replacement is still useful for reaching a different OpenSSL
         * negotiation branch, but doing it on half of all rounds repeatedly
         * erased useful seed structure. */
        if (rnd(100) < tls_policy_pct("profile", 50)) {
            /* Keep the original profile distribution until a profile-specific
             * coverage study justifies biasing it; OpenSSL's handshake cost
             * varies substantially by TLS 1.2/1.3 profile. */
            tls_make_client_hello_profile(p, rnd(10));
        } else {
            /* Keep the proven opt4 mix: 4/24 cipher, 5/24 extension, and
             * one each for session/random/compression. */
            switch (rnd(12)) {
                case 0: case 1: case 2: case 3:
                    mutate_client_hello_cipher_suites(p, 1); break;
                case 4: case 5: case 6: case 7: case 8:
                    mutate_client_hello_extensions(p, 1); break;
                case 9:
                    mutate_client_hello_session_id(p, 1); break;
                case 10:
                    mutate_client_hello_random(p, 1); break;
                default:
                    mutate_client_hello_compression_methods(p, 1); break;
            }
            tls_finalize_client_hello_packet(p);
        }

        /* Typed bodies are uncommon in the client-side seed, but when they
         * are present this keeps certificate/key-exchange/finished fields in
         * the mutation budget instead of silently ignoring them. */
        if (rnd(100) < tls_policy_pct("typed", 20))
            mutate_tls_typed_handshake_body(pkts, (size_t)num_packets);

        /* Retain the tail by default.  Drop it only often enough to explore
         * a clean post-ClientHello path; this avoids making most executions
         * terminate before OpenSSL's record and crypto code is reached. */
        if (rnd(100) < tls_policy_pct("tail", 28))
            tls_drop_encrypted_tail_after(pkts, num_packets, chosen_idx);
    }
}
