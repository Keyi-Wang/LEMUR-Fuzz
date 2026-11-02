// ssh_parser.c
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "ssh_packets.h"

typedef uint8_t u8;
typedef uint32_t u32;

typedef struct { const u8 *p; u32 len; u32 off; } cursor_t;

static int cur_has(cursor_t *c, u32 need) { return (need <= (c->len - c->off)); }
static const u8* cur_ptr(cursor_t *c) { return c->p + c->off; }
static void cur_advance(cursor_t *c, u32 n) { c->off += n; }

static int read_u32_be(const u8 *p, u32 *out) {
    *out = ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
    return 1;
}

static u32 min_u32(u32 a, u32 b) { return a < b ? a : b; }

static int ssh_field_eq(const ssh_string_field_t *f, const char *lit) {
    size_t n = strlen(lit);
    return f && f->len == n && memcmp(f->bytes, lit, n) == 0;
}

static int parse_ssh_banner_pkt(cursor_t *c, ssh_packet_t *out) {
    if (c->off >= c->len) return 0;
    u32 start = c->off;
    u32 max_scan = min_u32(SSH_MAX_BANNER_LEN, c->len - c->off);
    u32 i;
    int found = 0;
    for (i = 0; i + 1 < max_scan; ++i) {
        if (c->p[c->off + i] == '\r' && c->p[c->off + i + 1] == '\n') {
            found = 1;
            break;
        }
    }
    if (!found) return 0;
    u32 banner_len = i + 2;
    if (banner_len > SSH_MAX_BANNER_LEN) return 0;

    if (banner_len < 8) return 0;
    if (c->p[c->off + 0] != 'S' || c->p[c->off + 1] != 'S' || c->p[c->off + 2] != 'H' || c->p[c->off + 3] != '-') return 0;

    ssh_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = SSH_BANNER;
    ssh_banner_t *b = &pkt.u.banner;
    b->proto_id[0] = 'S'; b->proto_id[1] = 'S'; b->proto_id[2] = 'H'; b->proto_id[3] = '\0';
    b->dash1 = '-';
    b->protoversion[0] = '2'; b->protoversion[1] = '.'; b->protoversion[2] = '0'; b->protoversion[3] = '\0';
    b->dash2 = '-';
    b->cr = '\r'; b->lf = '\n';

    u32 pos = c->off;
    u32 end = c->off + banner_len;

    while (pos < end && c->p[pos] != '-' ) pos++;
    if (pos + 1 >= end) { return 0; }
    pos++;
    if (pos + 3 >= end) { return 0; }
    if (!(c->p[pos] == '2' && c->p[pos+1] == '.' && c->p[pos+2] == '0' && c->p[pos+3] == '-')) {
        // Not SSH-2.0-, but still a banner. Capture raw minimally.
        // For our model, require 2.0 as Fixed; otherwise fail.
        return 0;
    }
    pos += 4;
    u32 sw_start = pos;
    while (pos < end && c->p[pos] != '\r' && c->p[pos] != ' ')
        pos++;
    u32 software_len = (pos > sw_start) ? (pos - sw_start) : 0;
    if (software_len > SSH_MAX_BANNER_LEN) software_len = SSH_MAX_BANNER_LEN;
    if (software_len) {
        memcpy(b->software, c->p + sw_start, software_len);
    }
    b->software_len = (uint16_t)software_len;

    b->has_comments = 0;
    b->comments_len = 0;
    if (pos < end && c->p[pos] == ' ') {
        pos++;
        u32 com_start = pos;
        while (pos < end && c->p[pos] != '\r') pos++;
        u32 com_len = (pos > com_start) ? (pos - com_start) : 0;
        if (com_len > SSH_MAX_BANNER_LEN) com_len = SSH_MAX_BANNER_LEN;
        if (com_len) {
            memcpy(b->comments, c->p + com_start, com_len);
            b->has_comments = 1;
            b->comments_len = (uint16_t)com_len;
        }
    }

    b->raw_len = (uint16_t)banner_len;
    memcpy(b->raw, c->p + start, banner_len);

    *out = pkt;
    cur_advance(c, banner_len);
    return 1;
}

static int parse_string(cursor_t *pc, u32 max_copy, u32 *out_len, u8 *out_buf) {
    if (!cur_has(pc, 4)) return 0;
    u32 slen; read_u32_be(cur_ptr(pc), &slen);
    cur_advance(pc, 4);
    if (!cur_has(pc, slen) || slen > max_copy) return 0;
    u32 cpy = slen > max_copy ? max_copy : slen;
    if (cpy && out_buf) memcpy(out_buf, cur_ptr(pc), cpy);
    if (out_len) *out_len = cpy;
    cur_advance(pc, slen);
    return 1;
}

static int parse_namelist(cursor_t *pc, u32 *out_len, u8 *out_buf) {
    return parse_string(pc, SSH_MAX_NAMELIST_BYTES, out_len, out_buf);
}

static int parse_ssh_kexinit_payload(const u8 *payload, u32 payload_len, ssh_packet_t *out) {
    if (payload_len < 1 + 16 + 4*10 + 1 + 4) return 0;
    cursor_t p = { payload, payload_len, 0 };
    if (p.p[p.off] != SSH_MSG_KEXINIT) return 0;
    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_KEXINIT;
    ssh_kexinit_t *k = &pkt.u.kexinit;
    k->message_code = SSH_MSG_KEXINIT;
    cur_advance(&p, 1);
    if (!cur_has(&p, 16)) return 0;
    memcpy(k->cookie, cur_ptr(&p), 16); cur_advance(&p, 16);
    if (!parse_namelist(&p, &k->kex_algorithms_len, k->kex_algorithms)) return 0;
    if (!parse_namelist(&p, &k->server_host_key_algorithms_len, k->server_host_key_algorithms)) return 0;
    if (!parse_namelist(&p, &k->encryption_algorithms_client_to_server_len, k->encryption_algorithms_client_to_server)) return 0;
    if (!parse_namelist(&p, &k->encryption_algorithms_server_to_client_len, k->encryption_algorithms_server_to_client)) return 0;
    if (!parse_namelist(&p, &k->mac_algorithms_client_to_server_len, k->mac_algorithms_client_to_server)) return 0;
    if (!parse_namelist(&p, &k->mac_algorithms_server_to_client_len, k->mac_algorithms_server_to_client)) return 0;
    if (!parse_namelist(&p, &k->compression_algorithms_client_to_server_len, k->compression_algorithms_client_to_server)) return 0;
    if (!parse_namelist(&p, &k->compression_algorithms_server_to_client_len, k->compression_algorithms_server_to_client)) return 0;
    if (!parse_namelist(&p, &k->languages_client_to_server_len, k->languages_client_to_server)) return 0;
    if (!parse_namelist(&p, &k->languages_server_to_client_len, k->languages_server_to_client)) return 0;
    if (!cur_has(&p, 1 + 4)) return 0;
    k->first_kex_packet_follows = p.p[p.off]; cur_advance(&p, 1);
    u32 rsv; read_u32_be(cur_ptr(&p), &rsv); cur_advance(&p, 4);
    k->reserved_zero = rsv;
    *out = pkt;
    return 1;
}

static int parse_mpint(cursor_t *pc, u32 max_copy, u32 *out_len, u8 *out_buf) {
    if (!cur_has(pc, 4)) return 0;
    u32 mlen; read_u32_be(cur_ptr(pc), &mlen); cur_advance(pc, 4);
    if (!cur_has(pc, mlen) || mlen > max_copy) return 0;
    u32 cpy = mlen > max_copy ? max_copy : mlen;
    if (cpy && out_buf) memcpy(out_buf, cur_ptr(pc), cpy);
    if (out_len) *out_len = cpy;
    cur_advance(pc, mlen);
    return 1;
}

static int parse_ssh_kexdh_init_payload(const u8 *payload, u32 payload_len, ssh_packet_t *out) {
    if (payload_len < 1 + 4) return 0;
    cursor_t p = { payload, payload_len, 0 };
    if (p.p[p.off] != SSH_MSG_KEXDH_INIT) return 0;
    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_KEXDH_INIT;
    ssh_kexdh_init_t *d = &pkt.u.kexdh_init;
    d->message_code = SSH_MSG_KEXDH_INIT;
    cur_advance(&p, 1);
    if (!parse_mpint(&p, SSH_MAX_MPINT_BYTES, &d->e_len, d->e)) return 0;
    *out = pkt;
    return 1;
}

static int parse_ssh_service_request_payload(const u8 *payload, u32 payload_len, ssh_packet_t *out) {
    if (payload_len < 1 + 4) return 0;
    cursor_t p = (cursor_t){ payload, payload_len, 0 };
    if (p.p[p.off] != SSH_MSG_SERVICE_REQUEST) return 0;
    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_SERVICE_REQUEST;
    ssh_service_request_t *s = &pkt.u.service_request;
    s->message_code = SSH_MSG_SERVICE_REQUEST;
    cur_advance(&p, 1);
    u32 slen = 0;
    if (!parse_string(&p, SSH_MAX_SERVICE_NAME_BYTES, &slen, s->service_name)) return 0;
    s->service_name_len = slen;
    *out = pkt;
    return 1;
}

static int parse_ssh_newkeys_payload(const u8 *payload, u32 payload_len, ssh_packet_t *out) {
    if (payload_len < 1) return 0;
    if (payload[0] != SSH_MSG_NEWKEYS) return 0;
    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_NEWKEYS;
    pkt.u.newkeys.message_code = SSH_MSG_NEWKEYS;
    *out = pkt;
    return 1;
}

static int typed_read_u32(cursor_t *pc, u32 *out) {
    if (!cur_has(pc, 4)) return 0;
    read_u32_be(cur_ptr(pc), out);
    cur_advance(pc, 4);
    return 1;
}

static int typed_add_u32(ssh_typed_payload_t *tp, u32 v) {
    if (tp->uint32_count >= SSH_MAX_TYPED_UINT32_FIELDS) return 0;
    tp->uint32_values[tp->uint32_count++] = v;
    return 1;
}

static int typed_read_bool(cursor_t *pc, ssh_typed_payload_t *tp) {
    if (!cur_has(pc, 1)) return 0;
    uint8_t v = cur_ptr(pc)[0];
    if (tp->boolean_count < SSH_MAX_TYPED_BOOL_FIELDS) {
        if (tp->boolean_count == 0) tp->boolean_value = v;
        tp->boolean_values[tp->boolean_count++] = v;
    }
    cur_advance(pc, 1);
    return 1;
}

static int typed_read_string_field(cursor_t *pc, ssh_typed_payload_t *tp) {
    if (!cur_has(pc, 4)) return 0;
    u32 slen;
    read_u32_be(cur_ptr(pc), &slen);
    cur_advance(pc, 4);
    if (!cur_has(pc, slen)) return 0;
    if (slen > SSH_MAX_TYPED_FIELD_BYTES || tp->string_count >= SSH_MAX_TYPED_STRING_FIELDS) return 0;
    if (tp->string_count < SSH_MAX_TYPED_STRING_FIELDS) {
        ssh_string_field_t *f = &tp->strings[tp->string_count++];
        u32 copy = slen > SSH_MAX_TYPED_FIELD_BYTES ? SSH_MAX_TYPED_FIELD_BYTES : slen;
        f->len = copy;
        if (copy) memcpy(f->bytes, cur_ptr(pc), copy);
    }
    cur_advance(pc, slen);
    return 1;
}

static int typed_read_mpint_field(cursor_t *pc, ssh_typed_payload_t *tp) {
    return typed_read_string_field(pc, tp);
}

static void typed_copy_tail(cursor_t *pc, ssh_typed_payload_t *tp) {
    u32 remain = pc->len - pc->off;
    u32 copy = remain > SSH_MAX_TYPED_FIELD_BYTES ? SSH_MAX_TYPED_FIELD_BYTES : remain;
    tp->trailing_payload.len = copy;
    if (copy) memcpy(tp->trailing_payload.bytes, cur_ptr(pc), copy);
    cur_advance(pc, remain);
}

static int typed_expect_done_or_tail(cursor_t *pc, ssh_typed_payload_t *tp) {
    if (pc->len - pc->off > SSH_MAX_TYPED_FIELD_BYTES) return 0;
    if (pc->off < pc->len) typed_copy_tail(pc, tp);
    return 1;
}

static int parse_ssh_typed_fields(u8 code, const u8 *body, u32 body_len, ssh_typed_payload_t *tp) {
    cursor_t p = { body, body_len, 0 };
    u32 v = 0;
    tp->field_schema = code;
    tp->boolean_value = 0;
    tp->boolean_count = 0;
    tp->uint32_count = 0;
    tp->string_count = 0;
    tp->trailing_payload.len = 0;
    memset(tp->uint32_values, 0, sizeof(tp->uint32_values));
    memset(tp->boolean_values, 0, sizeof(tp->boolean_values));
    memset(tp->strings, 0, sizeof(tp->strings));

    switch (code) {
        case SSH_MSG_DISCONNECT:
            if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_IGNORE:
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_UNIMPLEMENTED:
            if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_DEBUG:
            if (!typed_read_bool(&p, tp)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_SERVICE_ACCEPT:
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_KEXDH_REPLY:
            if (!typed_read_string_field(&p, tp)) return 0;  // server public host key and certs
            if (!typed_read_mpint_field(&p, tp)) return 0;   // f
            if (!typed_read_string_field(&p, tp)) return 0;  // signature
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_KEX_DH_GEX_INIT:
            if (!typed_read_mpint_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_KEX_DH_GEX_REQUEST:
            for (int i = 0; i < 3; i++) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_USERAUTH_REQUEST:
            if (!typed_read_string_field(&p, tp)) return 0;  // user name
            if (!typed_read_string_field(&p, tp)) return 0;  // service name
            if (!typed_read_string_field(&p, tp)) return 0;  // method name
            if (ssh_field_eq(&tp->strings[2], "publickey")) {
                if (!typed_read_bool(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;  // public key algorithm
                if (!typed_read_string_field(&p, tp)) return 0;  // public key blob
                if (tp->boolean_value && p.off < p.len && !typed_read_string_field(&p, tp)) return 0; // signature
            } else if (ssh_field_eq(&tp->strings[2], "password")) {
                if (!typed_read_bool(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;  // password
                if (tp->boolean_value && p.off < p.len && !typed_read_string_field(&p, tp)) return 0; // new password
            } else if (ssh_field_eq(&tp->strings[2], "hostbased")) {
                if (!typed_read_string_field(&p, tp)) return 0;  // public key algorithm
                if (!typed_read_string_field(&p, tp)) return 0;  // public key blob
                if (!typed_read_string_field(&p, tp)) return 0;  // client host name
                if (!typed_read_string_field(&p, tp)) return 0;  // client user name
                if (p.off < p.len && !typed_read_string_field(&p, tp)) return 0; // signature
            } else if (ssh_field_eq(&tp->strings[2], "keyboard-interactive")) {
                if (!typed_read_string_field(&p, tp)) return 0;  // language tag
                if (!typed_read_string_field(&p, tp)) return 0;  // submethods name-list
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_USERAUTH_FAILURE:
            if (!typed_read_string_field(&p, tp)) return 0;  // name-list
            if (!typed_read_bool(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_USERAUTH_SUCCESS:
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_USERAUTH_BANNER:
            if (!typed_read_string_field(&p, tp)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_USERAUTH_METHOD_REPLY:
            if (!typed_read_string_field(&p, tp)) return 0;  // public key algorithm or method-specific string
            if (p.off < p.len && !typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_USERAUTH_INFO_RESPONSE:
            if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            for (u32 i = 0; i < v && i < SSH_MAX_TYPED_STRING_FIELDS; i++) {
                if (!typed_read_string_field(&p, tp)) return 0;
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_GLOBAL_REQUEST:
            if (!typed_read_string_field(&p, tp)) return 0;  // request name
            if (!typed_read_bool(&p, tp)) return 0;
            if (ssh_field_eq(&tp->strings[0], "tcpip-forward") ||
                ssh_field_eq(&tp->strings[0], "cancel-tcpip-forward")) {
                if (!typed_read_string_field(&p, tp)) return 0; // address_to_bind
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0; // port_to_bind
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_REQUEST_SUCCESS:
        case SSH_MSG_REQUEST_FAILURE:
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_OPEN:
            if (!typed_read_string_field(&p, tp)) return 0;
            for (int i = 0; i < 3; i++) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            }
            if (ssh_field_eq(&tp->strings[0], "x11")) {
                if (!typed_read_string_field(&p, tp)) return 0; // originator address
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0; // originator port
            } else if (ssh_field_eq(&tp->strings[0], "direct-tcpip") ||
                       ssh_field_eq(&tp->strings[0], "forwarded-tcpip")) {
                if (!typed_read_string_field(&p, tp)) return 0; // destination/address connected
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0; // destination port
                if (!typed_read_string_field(&p, tp)) return 0; // originator address
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0; // originator port
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
            for (int i = 0; i < 4; i++) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_OPEN_FAILURE:
            for (int i = 0; i < 2; i++) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            }
            if (!typed_read_string_field(&p, tp)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
            for (int i = 0; i < 2; i++) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            }
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_DATA:
            if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
            for (int i = 0; i < 2; i++) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            }
            if (!typed_read_string_field(&p, tp)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_EOF:
        case SSH_MSG_CHANNEL_CLOSE:
        case SSH_MSG_CHANNEL_SUCCESS:
        case SSH_MSG_CHANNEL_FAILURE:
            if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            return typed_expect_done_or_tail(&p, tp);
        case SSH_MSG_CHANNEL_REQUEST:
            if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            if (!typed_read_string_field(&p, tp)) return 0;
            if (!typed_read_bool(&p, tp)) return 0;
            if (ssh_field_eq(&tp->strings[0], "pty-req")) {
                if (!typed_read_string_field(&p, tp)) return 0; // TERM
                for (int i = 0; i < 4; i++) if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0; // terminal modes
            } else if (ssh_field_eq(&tp->strings[0], "x11-req")) {
                if (!typed_read_bool(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            } else if (ssh_field_eq(&tp->strings[0], "env")) {
                if (!typed_read_string_field(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;
            } else if (ssh_field_eq(&tp->strings[0], "exec") ||
                       ssh_field_eq(&tp->strings[0], "subsystem") ||
                       ssh_field_eq(&tp->strings[0], "signal")) {
                if (!typed_read_string_field(&p, tp)) return 0;
            } else if (ssh_field_eq(&tp->strings[0], "window-change")) {
                for (int i = 0; i < 4; i++) if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            } else if (ssh_field_eq(&tp->strings[0], "xon-xoff")) {
                if (!typed_read_bool(&p, tp)) return 0;
            } else if (ssh_field_eq(&tp->strings[0], "exit-status")) {
                if (!typed_read_u32(&p, &v) || !typed_add_u32(tp, v)) return 0;
            } else if (ssh_field_eq(&tp->strings[0], "exit-signal")) {
                if (!typed_read_string_field(&p, tp)) return 0;
                if (!typed_read_bool(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;
                if (!typed_read_string_field(&p, tp)) return 0;
            }
            return typed_expect_done_or_tail(&p, tp);
        default: /* GCOV_UNREACHABLE: parse_ssh_typed_payload only calls this for RFC-known typed messages. */
            tp->field_schema = 0; /* GCOV_UNREACHABLE */
            return 0; /* GCOV_UNREACHABLE */
    }
}


static ssh_packet_type_t ssh_type_for_message_code(u8 code) {
    switch (code) {
        case SSH_MSG_DISCONNECT: return SSH_DISCONNECT;
        case SSH_MSG_IGNORE: return SSH_IGNORE;
        case SSH_MSG_UNIMPLEMENTED: return SSH_UNIMPLEMENTED;
        case SSH_MSG_DEBUG: return SSH_DEBUG;
        case SSH_MSG_SERVICE_ACCEPT: return SSH_SERVICE_ACCEPT;
        case SSH_MSG_KEXDH_REPLY: return SSH_KEXDH_REPLY;
        case SSH_MSG_KEX_DH_GEX_INIT: return SSH_KEX_DH_GEX_INIT;
        case SSH_MSG_KEX_DH_GEX_REQUEST: return SSH_KEX_DH_GEX_REQUEST;
        case SSH_MSG_USERAUTH_REQUEST: return SSH_USERAUTH_REQUEST;
        case SSH_MSG_USERAUTH_FAILURE: return SSH_USERAUTH_FAILURE;
        case SSH_MSG_USERAUTH_SUCCESS: return SSH_USERAUTH_SUCCESS;
        case SSH_MSG_USERAUTH_BANNER: return SSH_USERAUTH_BANNER;
        case SSH_MSG_USERAUTH_METHOD_REPLY: return SSH_USERAUTH_METHOD_REPLY;
        case SSH_MSG_USERAUTH_INFO_RESPONSE: return SSH_USERAUTH_INFO_RESPONSE;
        case SSH_MSG_GLOBAL_REQUEST: return SSH_GLOBAL_REQUEST;
        case SSH_MSG_REQUEST_SUCCESS: return SSH_REQUEST_SUCCESS;
        case SSH_MSG_REQUEST_FAILURE: return SSH_REQUEST_FAILURE;
        case SSH_MSG_CHANNEL_OPEN: return SSH_CHANNEL_OPEN;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: return SSH_CHANNEL_OPEN_CONFIRMATION;
        case SSH_MSG_CHANNEL_OPEN_FAILURE: return SSH_CHANNEL_OPEN_FAILURE;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST: return SSH_CHANNEL_WINDOW_ADJUST;
        case SSH_MSG_CHANNEL_DATA: return SSH_CHANNEL_DATA;
        case SSH_MSG_CHANNEL_EXTENDED_DATA: return SSH_CHANNEL_EXTENDED_DATA;
        case SSH_MSG_CHANNEL_EOF: return SSH_CHANNEL_EOF;
        case SSH_MSG_CHANNEL_CLOSE: return SSH_CHANNEL_CLOSE;
        case SSH_MSG_CHANNEL_REQUEST: return SSH_CHANNEL_REQUEST;
        case SSH_MSG_CHANNEL_SUCCESS: return SSH_CHANNEL_SUCCESS;
        case SSH_MSG_CHANNEL_FAILURE: return SSH_CHANNEL_FAILURE;
        default: return SSH_TRANSPORT_PACKET;
    }
}

static int parse_ssh_typed_payload(const u8 *payload, u32 payload_len, ssh_packet_t *out) {
    if (!payload || payload_len < 1 || !out) return 0;
    ssh_packet_type_t t = ssh_type_for_message_code(payload[0]);
    if (t == SSH_TRANSPORT_PACKET) return 0;
    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
    pkt.type = t;
    pkt.u.typed.message_code = payload[0];
    u32 rest = payload_len - 1;
    if (rest > SSH_MAX_TYPED_PAYLOAD_BYTES) rest = SSH_MAX_TYPED_PAYLOAD_BYTES;
    pkt.u.typed.payload_len = rest;
    if (rest) memcpy(pkt.u.typed.payload, payload + 1, rest);
    /* Malformed typed payloads stay on the raw transport path.  Projecting
     * truncated RFC 4251 fields into a repaired message removes OpenSSH's
     * error-handling paths from the mutation search space. */
    if (!parse_ssh_typed_fields(payload[0], payload + 1, payload_len - 1, &pkt.u.typed)) return 0;
    *out = pkt;
    return 1;
}

static int classify_ssh_transport_payload(const ssh_packet_t *transport, ssh_packet_t *out) {
    if (!transport || !out || transport->type != SSH_TRANSPORT_PACKET) return 0;
    const ssh_transport_packet_t *t = &transport->u.transport;
    if (!t->has_message_code || t->payload_len < 1) return 0;
    switch (t->message_code) {
        case SSH_MSG_KEXINIT:
            return parse_ssh_kexinit_payload(t->payload, t->payload_len, out);
        case SSH_MSG_KEXDH_INIT:
            return parse_ssh_kexdh_init_payload(t->payload, t->payload_len, out);
        case SSH_MSG_SERVICE_REQUEST:
            return parse_ssh_service_request_payload(t->payload, t->payload_len, out);
        case SSH_MSG_NEWKEYS:
            return parse_ssh_newkeys_payload(t->payload, t->payload_len, out);
        default:
            return parse_ssh_typed_payload(t->payload, t->payload_len, out);
    }
}

static int parse_ssh_transport_packet(cursor_t *c, ssh_packet_t *out) {
    if (!cur_has(c, 4 + 1)) return 0;
    u32 packet_length; read_u32_be(cur_ptr(c), &packet_length);
    if (packet_length > SSH_MAX_WIRE_PACKET_BYTES) return 0;
    if (!cur_has(c, 4 + packet_length)) return 0;
    u8 padding_length = cur_ptr(c)[4];
    if (packet_length < (u32)padding_length + 1) return 0;
    u32 payload_len = packet_length - (u32)padding_length - 1u;
    const u8 *payload = cur_ptr(c) + 5;
    const u8 *padding = payload + payload_len;

    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
    pkt.type = SSH_TRANSPORT_PACKET;
    ssh_transport_packet_t *t = &pkt.u.transport;
    t->packet_length = packet_length;
    t->padding_length = padding_length;
    t->payload_len = min_u32(payload_len, SSH_MAX_WIRE_PACKET_BYTES);
    if (t->payload_len) memcpy(t->payload, payload, t->payload_len);
    u32 padcpy = padding_length;
    if (padcpy > SSH_MAX_PADDING_BYTES) padcpy = SSH_MAX_PADDING_BYTES;
    if (padcpy) memcpy(t->padding, padding, padcpy);
    if (payload_len >= 1) { t->has_message_code = 1; t->message_code = payload[0]; }
    *out = pkt;
    cur_advance(c, 4 + packet_length);
    return 1;
}

static int parse_ssh_opaque_pkt(cursor_t *c, ssh_packet_t *out) {
    if (c->off >= c->len) return 0;
    u32 remain = c->len - c->off;
    ssh_packet_t pkt; memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_OPAQUE;
    u32 cpy = remain > SSH_MAX_OPAQUE_BYTES ? SSH_MAX_OPAQUE_BYTES : remain;
    pkt.u.opaque.len = cpy;
    memcpy(pkt.u.opaque.bytes, cur_ptr(c), cpy);
    *out = pkt;
    if (remain > cpy) {
        pkt.u.opaque.overflow = cur_ptr(c) + cpy;
        pkt.u.opaque.overflow_len = remain - cpy;
        *out = pkt;
    }
    cur_advance(c, remain);
    return 1;
}

size_t parse_ssh_msg(const u8 *buf, u32 buf_len, ssh_packet_t *out_packets, u32 max_count) {
    if (!buf || !out_packets || max_count == 0) return 0;
    cursor_t c = { buf, buf_len, 0 };
    u32 out_idx = 0;

    ssh_packet_t tmp;
    if (out_idx < max_count && parse_ssh_banner_pkt(&c, &tmp)) {
        tmp.wire = buf;
        tmp.wire_len = c.off;
        out_packets[out_idx++] = tmp;
    }

    while (out_idx < max_count) {
        if (c.off >= c.len) break;
        ssh_packet_t pkt;
        u32 before = c.off;
        if (!parse_ssh_transport_packet(&c, &pkt)) {
            if (c.off == before) {
                if (out_idx < max_count && parse_ssh_opaque_pkt(&c, &pkt)) {
                    out_packets[out_idx++] = pkt;
                    break;
                }
            }
            break; /* GCOV_UNREACHABLE: parse_ssh_opaque_pkt cannot fail while c.off < c.len. */
        }
        ssh_packet_t classified;
        if (classify_ssh_transport_payload(&pkt, &classified)) {
            classified.has_transport_padding = 1;
            classified.transport_padding_length = pkt.u.transport.padding_length;
            classified.transport_payload_length = pkt.u.transport.payload_len;
            memcpy(classified.transport_padding, pkt.u.transport.padding, pkt.u.transport.padding_length);
            classified.wire = buf + before;
            classified.wire_len = c.off - before;
            out_packets[out_idx++] = classified;
        } else {
            pkt.wire = buf + before;
            pkt.wire_len = c.off - before;
            out_packets[out_idx++] = pkt;
        }
    }

    if (out_idx == 0) return 0;
    return c.off == c.len ? out_idx : 0;
}
