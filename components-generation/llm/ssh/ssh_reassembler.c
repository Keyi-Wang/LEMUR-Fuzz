// ssh_reassembler.c
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ssh_packets.h"

typedef uint8_t u8;
typedef uint32_t u32;

typedef struct { u8 *p; u32 cap; u32 off; } wb_t;

static int wb_has(wb_t *w, u32 need) { return need <= (w->cap - w->off); }
static int wb_put_u8(wb_t *w, u8 v) { if (!wb_has(w,1)) return 0; w->p[w->off++] = v; return 1; }
static int wb_put_u32_be(wb_t *w, u32 v) { if (!wb_has(w,4)) return 0; w->p[w->off++] = (u8)(v>>24); w->p[w->off++] = (u8)(v>>16); w->p[w->off++] = (u8)(v>>8); w->p[w->off++] = (u8)(v); return 1; }
static int wb_put_bytes(wb_t *w, const u8 *src, u32 n) { if (n==0) return 1; if (!wb_has(w,n)) return 0; memcpy(w->p + w->off, src, n); w->off += n; return 1; }


static u32 ssh_bound_len(u32 len, u32 max) { return len > max ? max : len; }

static int wb_put_ssh_string(wb_t *w, const ssh_string_field_t *f) {
    u32 len = f ? f->len : 0;
    if (len > SSH_MAX_TYPED_FIELD_BYTES) len = SSH_MAX_TYPED_FIELD_BYTES;
    if (!wb_put_u32_be(w, len)) return 0;
    if (len && !wb_put_bytes(w, f->bytes, len)) return 0;
    return 1;
}

static const ssh_string_field_t *ssh_str_at(const ssh_typed_payload_t *tp, u32 idx) {
    static const ssh_string_field_t empty = {0, {0}};
    if (!tp || idx >= tp->string_count || idx >= SSH_MAX_TYPED_STRING_FIELDS) return &empty;
    return &tp->strings[idx];
}

static u32 ssh_u32_at(const ssh_typed_payload_t *tp, u32 idx) {
    if (!tp || idx >= tp->uint32_count || idx >= SSH_MAX_TYPED_UINT32_FIELDS) return 0;
    return tp->uint32_values[idx];
}

static uint8_t ssh_bool_at(const ssh_typed_payload_t *tp, u32 idx) {
    if (!tp) return 0;
    if (idx < tp->boolean_count && idx < SSH_MAX_TYPED_BOOL_FIELDS) return tp->boolean_values[idx];
    if (idx == 0) return tp->boolean_value;
    return 0;
}

static int ssh_field_eq(const ssh_string_field_t *f, const char *lit) {
    size_t n = strlen(lit);
    return f && f->len == n && memcmp(f->bytes, lit, n) == 0;
}


static uint8_t ssh_default_message_code(ssh_packet_type_t type) {
    switch (type) {
        case SSH_DISCONNECT: return SSH_MSG_DISCONNECT;
        case SSH_IGNORE: return SSH_MSG_IGNORE;
        case SSH_UNIMPLEMENTED: return SSH_MSG_UNIMPLEMENTED;
        case SSH_DEBUG: return SSH_MSG_DEBUG;
        case SSH_SERVICE_ACCEPT: return SSH_MSG_SERVICE_ACCEPT;
        case SSH_KEXDH_REPLY: return SSH_MSG_KEXDH_REPLY;
        case SSH_KEX_DH_GEX_INIT: return SSH_MSG_KEX_DH_GEX_INIT;
        case SSH_KEX_DH_GEX_REQUEST: return SSH_MSG_KEX_DH_GEX_REQUEST;
        case SSH_USERAUTH_REQUEST: return SSH_MSG_USERAUTH_REQUEST;
        case SSH_USERAUTH_FAILURE: return SSH_MSG_USERAUTH_FAILURE;
        case SSH_USERAUTH_SUCCESS: return SSH_MSG_USERAUTH_SUCCESS;
        case SSH_USERAUTH_BANNER: return SSH_MSG_USERAUTH_BANNER;
        case SSH_USERAUTH_METHOD_REPLY: return SSH_MSG_USERAUTH_METHOD_REPLY;
        case SSH_USERAUTH_INFO_RESPONSE: return SSH_MSG_USERAUTH_INFO_RESPONSE;
        case SSH_GLOBAL_REQUEST: return SSH_MSG_GLOBAL_REQUEST;
        case SSH_REQUEST_SUCCESS: return SSH_MSG_REQUEST_SUCCESS;
        case SSH_REQUEST_FAILURE: return SSH_MSG_REQUEST_FAILURE;
        case SSH_CHANNEL_OPEN: return SSH_MSG_CHANNEL_OPEN;
        case SSH_CHANNEL_OPEN_CONFIRMATION: return SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
        case SSH_CHANNEL_OPEN_FAILURE: return SSH_MSG_CHANNEL_OPEN_FAILURE;
        case SSH_CHANNEL_WINDOW_ADJUST: return SSH_MSG_CHANNEL_WINDOW_ADJUST;
        case SSH_CHANNEL_DATA: return SSH_MSG_CHANNEL_DATA;
        case SSH_CHANNEL_EXTENDED_DATA: return SSH_MSG_CHANNEL_EXTENDED_DATA;
        case SSH_CHANNEL_EOF: return SSH_MSG_CHANNEL_EOF;
        case SSH_CHANNEL_CLOSE: return SSH_MSG_CHANNEL_CLOSE;
        case SSH_CHANNEL_REQUEST: return SSH_MSG_CHANNEL_REQUEST;
        case SSH_CHANNEL_SUCCESS: return SSH_MSG_CHANNEL_SUCCESS;
        case SSH_CHANNEL_FAILURE: return SSH_MSG_CHANNEL_FAILURE;
        default: return 0; /* GCOV_UNREACHABLE: caller dispatches only known typed packet kinds. */
    }
}

static int reassemble_payload_as_transport(const u8 *payload, u32 payload_len, wb_t *w) {
    u32 min_pad = 4;
    u32 no_mac_total = 1 + payload_len + min_pad;
    u32 block = 8;
    u32 rem = no_mac_total % block;
    u32 padding_len = rem ? (block - rem) : block;
    if (padding_len < 4) padding_len += block;
    if (padding_len > SSH_MAX_PADDING_BYTES) return 1;
    u32 packet_length = 1 + payload_len + padding_len;
    if (!wb_put_u32_be(w, packet_length)) return 1;
    if (!wb_put_u8(w, (u8)padding_len)) return 1;
    if (payload_len && !wb_put_bytes(w, payload, payload_len)) return 1;
    u8 pad[SSH_MAX_PADDING_BYTES];
    for (u32 i = 0; i < padding_len; ++i) pad[i] = (u8)(0xA5u ^ i);
    if (!wb_put_bytes(w, pad, padding_len)) return 1;
    return 0;
}

static int reassemble_SSH_BANNER(const ssh_banner_t *b, wb_t *w) {
    if (b->raw_len >= 1 && b->raw_len <= SSH_MAX_BANNER_LEN) {
        if (!wb_put_bytes(w, b->raw, b->raw_len)) return 1;
        return 0;
    }
    if (!wb_put_bytes(w, (const u8*)"SSH-", 4)) return 1;
    if (!wb_put_bytes(w, (const u8*)"2.0-", 4)) return 1;
    if (b->software_len) { if (!wb_put_bytes(w, (const u8*)b->software, b->software_len)) return 1; }
    if (b->has_comments && b->comments_len) {
        if (!wb_put_u8(w, (u8)' ')) return 1;
        if (!wb_put_bytes(w, (const u8*)b->comments, b->comments_len)) return 1;
    }
    if (!wb_put_u8(w, (u8) '\r')) return 1;
    if (!wb_put_u8(w, (u8) '\n')) return 1;
    return 0;
}

static int reassemble_SSH_TRANSPORT_PACKET(const ssh_transport_packet_t *t, wb_t *w) {
    u32 packet_length = t->packet_length;
    u8 padding_length = t->padding_length;
    u32 payload_len = t->payload_len;
    if (payload_len > SSH_MAX_WIRE_PACKET_BYTES) return 1;
    if (packet_length != (1u + payload_len + (u32)padding_length)) return 1;
    if (!wb_put_u32_be(w, packet_length)) return 1;
    if (!wb_put_u8(w, padding_length)) return 1;
    if (payload_len && !wb_put_bytes(w, t->payload, payload_len)) return 1;
    if (padding_length && !wb_put_bytes(w, t->padding, padding_length)) return 1;
    return 0;
}

static int reassemble_SSH_KEXINIT(const ssh_kexinit_t *k, wb_t *w) {
    u32 kex_len = ssh_bound_len(k->kex_algorithms_len, SSH_MAX_NAMELIST_BYTES);
    u32 hostkey_len = ssh_bound_len(k->server_host_key_algorithms_len, SSH_MAX_NAMELIST_BYTES);
    u32 enc_c2s_len = ssh_bound_len(k->encryption_algorithms_client_to_server_len, SSH_MAX_NAMELIST_BYTES);
    u32 enc_s2c_len = ssh_bound_len(k->encryption_algorithms_server_to_client_len, SSH_MAX_NAMELIST_BYTES);
    u32 mac_c2s_len = ssh_bound_len(k->mac_algorithms_client_to_server_len, SSH_MAX_NAMELIST_BYTES);
    u32 mac_s2c_len = ssh_bound_len(k->mac_algorithms_server_to_client_len, SSH_MAX_NAMELIST_BYTES);
    u32 comp_c2s_len = ssh_bound_len(k->compression_algorithms_client_to_server_len, SSH_MAX_NAMELIST_BYTES);
    u32 comp_s2c_len = ssh_bound_len(k->compression_algorithms_server_to_client_len, SSH_MAX_NAMELIST_BYTES);
    u32 lang_c2s_len = ssh_bound_len(k->languages_client_to_server_len, SSH_MAX_NAMELIST_BYTES);
    u32 lang_s2c_len = ssh_bound_len(k->languages_server_to_client_len, SSH_MAX_NAMELIST_BYTES);

    u32 total = 1 + 16;
    total += 4 + kex_len;
    total += 4 + hostkey_len;
    total += 4 + enc_c2s_len;
    total += 4 + enc_s2c_len;
    total += 4 + mac_c2s_len;
    total += 4 + mac_s2c_len;
    total += 4 + comp_c2s_len;
    total += 4 + comp_s2c_len;
    total += 4 + lang_c2s_len;
    total += 4 + lang_s2c_len;
    total += 1 + 4;
    u32 payload_len = total;

    u32 min_pad = 4;
    u32 no_mac_total = 1 + payload_len + min_pad;
    u32 block = 8;
    u32 rem = no_mac_total % block;
    u32 padding_len = rem ? (block - rem) : block;
    if (padding_len < 4) padding_len += block;
    if (padding_len > SSH_MAX_PADDING_BYTES) return 1;
    u32 packet_length = 1 + payload_len + padding_len;

    if (!wb_put_u32_be(w, packet_length)) return 1;
    if (!wb_put_u8(w, (u8)padding_len)) return 1;
    if (!wb_put_u8(w, SSH_MSG_KEXINIT)) return 1;
    if (!wb_put_bytes(w, k->cookie, 16)) return 1;

    if (!wb_put_u32_be(w, kex_len)) return 1;
    if (kex_len && !wb_put_bytes(w, k->kex_algorithms, kex_len)) return 1;
    if (!wb_put_u32_be(w, hostkey_len)) return 1;
    if (hostkey_len && !wb_put_bytes(w, k->server_host_key_algorithms, hostkey_len)) return 1;
    if (!wb_put_u32_be(w, enc_c2s_len)) return 1;
    if (enc_c2s_len && !wb_put_bytes(w, k->encryption_algorithms_client_to_server, enc_c2s_len)) return 1;
    if (!wb_put_u32_be(w, enc_s2c_len)) return 1;
    if (enc_s2c_len && !wb_put_bytes(w, k->encryption_algorithms_server_to_client, enc_s2c_len)) return 1;
    if (!wb_put_u32_be(w, mac_c2s_len)) return 1;
    if (mac_c2s_len && !wb_put_bytes(w, k->mac_algorithms_client_to_server, mac_c2s_len)) return 1;
    if (!wb_put_u32_be(w, mac_s2c_len)) return 1;
    if (mac_s2c_len && !wb_put_bytes(w, k->mac_algorithms_server_to_client, mac_s2c_len)) return 1;
    if (!wb_put_u32_be(w, comp_c2s_len)) return 1;
    if (comp_c2s_len && !wb_put_bytes(w, k->compression_algorithms_client_to_server, comp_c2s_len)) return 1;
    if (!wb_put_u32_be(w, comp_s2c_len)) return 1;
    if (comp_s2c_len && !wb_put_bytes(w, k->compression_algorithms_server_to_client, comp_s2c_len)) return 1;
    if (!wb_put_u32_be(w, lang_c2s_len)) return 1;
    if (lang_c2s_len && !wb_put_bytes(w, k->languages_client_to_server, lang_c2s_len)) return 1;
    if (!wb_put_u32_be(w, lang_s2c_len)) return 1;
    if (lang_s2c_len && !wb_put_bytes(w, k->languages_server_to_client, lang_s2c_len)) return 1;

    if (!wb_put_u8(w, k->first_kex_packet_follows ? 1 : 0)) return 1;
    if (!wb_put_u32_be(w, 0)) return 1;

    u8 pad[SSH_MAX_PADDING_BYTES];
    for (u32 i = 0; i < padding_len; ++i) pad[i] = (u8)(i & 0xFF);
    if (padding_len && !wb_put_bytes(w, pad, padding_len)) return 1;

    return 0;
}

static int reassemble_SSH_KEXDH_INIT(const ssh_kexdh_init_t *d, wb_t *w) {
    u32 e_len = ssh_bound_len(d->e_len, SSH_MAX_MPINT_BYTES);
    u32 payload_len = 1 + 4 + e_len;
    u32 min_pad = 4;
    u32 no_mac_total = 1 + payload_len + min_pad;
    u32 block = 8;
    u32 rem = no_mac_total % block;
    u32 padding_len = rem ? (block - rem) : block;
    if (padding_len < 4) padding_len += block;
    u32 packet_length = 1 + payload_len + padding_len;

    if (!wb_put_u32_be(w, packet_length)) return 1;
    if (!wb_put_u8(w, (u8)padding_len)) return 1;
    if (!wb_put_u8(w, SSH_MSG_KEXDH_INIT)) return 1;
    if (!wb_put_u32_be(w, e_len)) return 1;
    if (e_len && !wb_put_bytes(w, d->e, e_len)) return 1;

    u8 pad[SSH_MAX_PADDING_BYTES];
    for (u32 i = 0; i < padding_len; ++i) pad[i] = (u8)(i & 0xFF);
    if (padding_len && !wb_put_bytes(w, pad, padding_len)) return 1;
    return 0;
}

static int reassemble_SSH_SERVICE_REQUEST(const ssh_service_request_t *s, wb_t *w) {
    u32 service_name_len = ssh_bound_len(s->service_name_len, SSH_MAX_SERVICE_NAME_BYTES);
    u32 payload_len = 1 + 4 + service_name_len;
    u32 min_pad = 4;
    u32 no_mac_total = 1 + payload_len + min_pad;
    u32 block = 8;
    u32 rem = no_mac_total % block;
    u32 padding_len = rem ? (block - rem) : block;
    if (padding_len < 4) padding_len += block;
    u32 packet_length = 1 + payload_len + padding_len;

    if (!wb_put_u32_be(w, packet_length)) return 1;
    if (!wb_put_u8(w, (u8)padding_len)) return 1;
    if (!wb_put_u8(w, SSH_MSG_SERVICE_REQUEST)) return 1;
    if (!wb_put_u32_be(w, service_name_len)) return 1;
    if (service_name_len && !wb_put_bytes(w, s->service_name, service_name_len)) return 1;

    u8 pad[SSH_MAX_PADDING_BYTES];
    for (u32 i = 0; i < padding_len; ++i) pad[i] = (u8)(i & 0xFF);
    if (padding_len && !wb_put_bytes(w, pad, padding_len)) return 1;
    return 0;
}

static int reassemble_SSH_NEWKEYS(const ssh_newkeys_t *n, wb_t *w) {
    (void)n;
    u32 payload_len = 1;
    u32 min_pad = 4;
    u32 no_mac_total = 1 + payload_len + min_pad;
    u32 block = 8;
    u32 rem = no_mac_total % block;
    u32 padding_len = rem ? (block - rem) : block;
    if (padding_len < 4) padding_len += block;
    u32 packet_length = 1 + payload_len + padding_len;

    if (!wb_put_u32_be(w, packet_length)) return 1;
    if (!wb_put_u8(w, (u8)padding_len)) return 1;
    if (!wb_put_u8(w, SSH_MSG_NEWKEYS)) return 1;

    u8 pad[SSH_MAX_PADDING_BYTES];
    for (u32 i = 0; i < padding_len; ++i) pad[i] = (u8)(i & 0xFF);
    if (padding_len && !wb_put_bytes(w, pad, padding_len)) return 1;
    return 0;
}


static int reassemble_SSH_TYPED(ssh_packet_type_t type, const ssh_typed_payload_t *tp, wb_t *w) {
    if (!tp) return 1;
    u8 code = tp->message_code ? tp->message_code : ssh_default_message_code(type);
    if (tp->field_schema) {
        u8 payload[SSH_MAX_TYPED_PAYLOAD_BYTES + 1u];
        wb_t pw = { payload, sizeof(payload), 0 };
        if (!wb_put_u8(&pw, code)) return 1;
        switch (code) {
            case SSH_MSG_DISCONNECT:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                break;
            case SSH_MSG_IGNORE:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                break;
            case SSH_MSG_UNIMPLEMENTED:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                break;
            case SSH_MSG_DEBUG:
                if (!wb_put_u8(&pw, tp->boolean_value)) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                break;
            case SSH_MSG_SERVICE_ACCEPT:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                break;
            case SSH_MSG_KEXDH_REPLY:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                break;
            case SSH_MSG_KEX_DH_GEX_INIT:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                break;
            case SSH_MSG_KEX_DH_GEX_REQUEST:
                for (u32 i = 0; i < 3; i++) if (!wb_put_u32_be(&pw, ssh_u32_at(tp, i))) return 1;
                break;
            case SSH_MSG_USERAUTH_REQUEST:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                if (ssh_field_eq(ssh_str_at(tp, 2), "publickey")) {
                    if (!wb_put_u8(&pw, tp->boolean_value)) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 3))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 4))) return 1;
                    if (tp->boolean_value && !wb_put_ssh_string(&pw, ssh_str_at(tp, 5))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 2), "password")) {
                    if (!wb_put_u8(&pw, tp->boolean_value)) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 3))) return 1;
                    if (tp->boolean_value && !wb_put_ssh_string(&pw, ssh_str_at(tp, 4))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 2), "hostbased")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 3))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 4))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 5))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 6))) return 1;
                    if (tp->string_count > 7 && !wb_put_ssh_string(&pw, ssh_str_at(tp, 7))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 2), "keyboard-interactive")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 3))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 4))) return 1;
                }
                break;
            case SSH_MSG_USERAUTH_FAILURE:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_u8(&pw, tp->boolean_value)) return 1;
                break;
            case SSH_MSG_USERAUTH_SUCCESS:
            case SSH_MSG_REQUEST_SUCCESS:
            case SSH_MSG_REQUEST_FAILURE:
                break;
            case SSH_MSG_USERAUTH_BANNER:
            case SSH_MSG_USERAUTH_METHOD_REPLY:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (tp->string_count > 1 && !wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                break;
            case SSH_MSG_USERAUTH_INFO_RESPONSE:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                for (u32 i = 0; i < tp->string_count && i < SSH_MAX_TYPED_STRING_FIELDS; i++)
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, i))) return 1;
                break;
            case SSH_MSG_GLOBAL_REQUEST:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_u8(&pw, ssh_bool_at(tp, 0))) return 1;
                if (ssh_field_eq(ssh_str_at(tp, 0), "tcpip-forward") ||
                    ssh_field_eq(ssh_str_at(tp, 0), "cancel-tcpip-forward")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                }
                break;
            case SSH_MSG_CHANNEL_OPEN:
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 1))) return 1;
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 2))) return 1;
                if (ssh_field_eq(ssh_str_at(tp, 0), "x11")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 3))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "direct-tcpip") ||
                           ssh_field_eq(ssh_str_at(tp, 0), "forwarded-tcpip")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 3))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                    if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 4))) return 1;
                }
                break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                for (u32 i = 0; i < 4; i++) if (!wb_put_u32_be(&pw, ssh_u32_at(tp, i))) return 1;
                break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 1))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                break;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 1))) return 1;
                break;
            case SSH_MSG_CHANNEL_DATA:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                break;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 1))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                break;
            case SSH_MSG_CHANNEL_EOF:
            case SSH_MSG_CHANNEL_CLOSE:
            case SSH_MSG_CHANNEL_SUCCESS:
            case SSH_MSG_CHANNEL_FAILURE:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                break;
            case SSH_MSG_CHANNEL_REQUEST:
                if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 0))) return 1;
                if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 0))) return 1;
                if (!wb_put_u8(&pw, ssh_bool_at(tp, 0))) return 1;
                if (ssh_field_eq(ssh_str_at(tp, 0), "pty-req")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    for (u32 i = 1; i <= 4; i++) if (!wb_put_u32_be(&pw, ssh_u32_at(tp, i))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "x11-req")) {
                    if (!wb_put_u8(&pw, ssh_bool_at(tp, 1))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                    if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 1))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "env")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "exec") ||
                           ssh_field_eq(ssh_str_at(tp, 0), "subsystem") ||
                           ssh_field_eq(ssh_str_at(tp, 0), "signal")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "window-change")) {
                    for (u32 i = 1; i <= 4; i++) if (!wb_put_u32_be(&pw, ssh_u32_at(tp, i))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "xon-xoff")) {
                    if (!wb_put_u8(&pw, ssh_bool_at(tp, 1))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "exit-status")) {
                    if (!wb_put_u32_be(&pw, ssh_u32_at(tp, 1))) return 1;
                } else if (ssh_field_eq(ssh_str_at(tp, 0), "exit-signal")) {
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 1))) return 1;
                    if (!wb_put_u8(&pw, ssh_bool_at(tp, 1))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 2))) return 1;
                    if (!wb_put_ssh_string(&pw, ssh_str_at(tp, 3))) return 1;
                }
                break;
            default:
                return 1;
        }
        if (tp->trailing_payload.len) {
            u32 tail = tp->trailing_payload.len;
            if (tail > SSH_MAX_TYPED_FIELD_BYTES) tail = SSH_MAX_TYPED_FIELD_BYTES;
            if (!wb_put_bytes(&pw, tp->trailing_payload.bytes, tail)) return 1;
        }
        return reassemble_payload_as_transport(payload, pw.off, w);
    }
    u32 rest = tp->payload_len;
    if (rest > SSH_MAX_TYPED_PAYLOAD_BYTES) rest = SSH_MAX_TYPED_PAYLOAD_BYTES;
    if (rest + 1 > SSH_MAX_WIRE_PACKET_BYTES) return 1;
    u8 payload[SSH_MAX_TYPED_PAYLOAD_BYTES + 1u];
    payload[0] = code;
    if (rest) memcpy(payload + 1, tp->payload, rest);
    return reassemble_payload_as_transport(payload, rest + 1, w);
}

static int reassemble_SSH_OPAQUE(const ssh_opaque_t *o, wb_t *w) {
    if (!o->len) return 0;
    if (o->len > SSH_MAX_OPAQUE_BYTES || !wb_put_bytes(w, o->bytes, o->len)) return 1;
    if (o->overflow_len && (!o->overflow || !wb_put_bytes(w, o->overflow, o->overflow_len))) return 1;
    return 0;
}

int reassemble_ssh_msgs(const ssh_packet_t *packets, u32 num_packets, u8 *output_buf, u32 *out_len) {
    if (!packets || !output_buf || !out_len) return 1;
    wb_t w = { output_buf, *out_len, 0 };
    for (u32 i = 0; i < num_packets; ++i) {
        if (packets[i].wire && packets[i].wire_len) {
            if (!wb_put_bytes(&w, packets[i].wire, packets[i].wire_len)) return 1;
            continue;
        }
        int rc = 1;
        u32 start = w.off;
        switch (packets[i].type) {
            case SSH_BANNER: rc = reassemble_SSH_BANNER(&packets[i].u.banner, &w); break;
            case SSH_TRANSPORT_PACKET: rc = reassemble_SSH_TRANSPORT_PACKET(&packets[i].u.transport, &w); break;
            case SSH_KEXINIT: rc = reassemble_SSH_KEXINIT(&packets[i].u.kexinit, &w); break;
            case SSH_KEXDH_INIT: rc = reassemble_SSH_KEXDH_INIT(&packets[i].u.kexdh_init, &w); break;
            case SSH_SERVICE_REQUEST: rc = reassemble_SSH_SERVICE_REQUEST(&packets[i].u.service_request, &w); break;
            case SSH_NEWKEYS: rc = reassemble_SSH_NEWKEYS(&packets[i].u.newkeys, &w); break;
            case SSH_OPAQUE: rc = reassemble_SSH_OPAQUE(&packets[i].u.opaque, &w); break;
            case SSH_DISCONNECT:
            case SSH_IGNORE:
            case SSH_UNIMPLEMENTED:
            case SSH_DEBUG:
            case SSH_SERVICE_ACCEPT:
            case SSH_KEXDH_REPLY:
            case SSH_KEX_DH_GEX_INIT:
            case SSH_KEX_DH_GEX_REQUEST:
            case SSH_USERAUTH_REQUEST:
            case SSH_USERAUTH_FAILURE:
            case SSH_USERAUTH_SUCCESS:
            case SSH_USERAUTH_BANNER:
            case SSH_USERAUTH_METHOD_REPLY:
            case SSH_USERAUTH_INFO_RESPONSE:
            case SSH_GLOBAL_REQUEST:
            case SSH_REQUEST_SUCCESS:
            case SSH_REQUEST_FAILURE:
            case SSH_CHANNEL_OPEN:
            case SSH_CHANNEL_OPEN_CONFIRMATION:
            case SSH_CHANNEL_OPEN_FAILURE:
            case SSH_CHANNEL_WINDOW_ADJUST:
            case SSH_CHANNEL_DATA:
            case SSH_CHANNEL_EXTENDED_DATA:
            case SSH_CHANNEL_EOF:
            case SSH_CHANNEL_CLOSE:
            case SSH_CHANNEL_REQUEST:
            case SSH_CHANNEL_SUCCESS:
            case SSH_CHANNEL_FAILURE:
                rc = reassemble_SSH_TYPED(packets[i].type, &packets[i].u.typed, &w); break;
            default: return 1;
        }
        if (rc != 0) return rc;
        const ssh_packet_t *p = &packets[i];
        if (p->has_transport_padding && p->type != SSH_BANNER &&
            p->type != SSH_OPAQUE && p->type != SSH_TRANSPORT_PACKET && w.off >= start + 5) {
            u32 generated_padding = w.p[start + 4];
            u32 payload_len = w.off - start - 5 - generated_padding;
            if (payload_len == p->transport_payload_length) {
                u32 original_padding = p->transport_padding_length;
                if (original_padding > SSH_MAX_PADDING_BYTES) original_padding = SSH_MAX_PADDING_BYTES;
                u32 length = 1 + payload_len + original_padding;
                if (start + 4 + length > w.cap) return 1;
                w.p[start] = (u8)(length >> 24); w.p[start+1] = (u8)(length >> 16);
                w.p[start+2] = (u8)(length >> 8); w.p[start+3] = (u8)length;
                w.p[start+4] = (u8)original_padding;
                memcpy(w.p + start + 5 + payload_len, p->transport_padding, original_padding);
                w.off = start + 4 + length;
            }
        }
    }
    *out_len = w.off;
    return 0;
}
