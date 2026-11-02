#include "ssh_packets.h"

#include <string.h>

static void set_bytes(unsigned char *dst, uint32_t *len, uint32_t max, const char *s)
{
    if (!dst || !len || !s) return;
    size_t n = strlen(s);
    if (n > max) n = max;
    memcpy(dst, s, n);
    *len = (uint32_t)n;
}

static void set_field(ssh_string_field_t *f, const char *s)
{
    if (!f || !s) return;
    uint32_t len = 0;
    set_bytes(f->bytes, &len, SSH_MAX_TYPED_FIELD_BYTES, s);
    f->len = len;
}

static int namelist_looks_valid(const unsigned char *s, uint32_t len)
{
    if (!s || len == 0) return 0;
    if (s[0] == ',' || s[len - 1] == ',') return 0;
    for (uint32_t i = 0; i < len; ++i) {
        unsigned char c = s[i];
        if (c < 0x21 || c > 0x7e || c == ' ') return 0;
        if (c == ',' && i + 1 < len && s[i + 1] == ',') return 0;
    }
    return 1;
}

static int string_eq(const unsigned char *s, uint32_t len, const char *lit)
{
    size_t n = strlen(lit);
    return len == n && memcmp(s, lit, n) == 0;
}

static uint32_t ssh_padding_for_payload(uint32_t payload_len)
{
    uint32_t pad = 4;
    while (pad <= SSH_MAX_PADDING_BYTES) {
        uint32_t packet_length = 1u + payload_len + pad;
        if (((packet_length + 4u) % 8u) == 0) return pad;
        pad++;
    }
    return 4;
}

static int ssh_valid_service_name(const ssh_string_field_t *f)
{
    return f && (string_eq(f->bytes, f->len, "ssh-userauth") ||
                 string_eq(f->bytes, f->len, "ssh-connection"));
}

static int ssh_valid_userauth_method(const ssh_string_field_t *f)
{
    return f && (string_eq(f->bytes, f->len, "none") ||
                 string_eq(f->bytes, f->len, "password") ||
                 string_eq(f->bytes, f->len, "publickey") ||
                 string_eq(f->bytes, f->len, "hostbased") ||
                 string_eq(f->bytes, f->len, "keyboard-interactive"));
}

static int ssh_field_is(const ssh_string_field_t *f, const char *lit)
{
    return f && string_eq(f->bytes, f->len, lit);
}


static void fix_bool_value(uint8_t *v)
{
    if (v) *v = *v ? 1u : 0u;
}

static void fix_typed_boolean_count(ssh_typed_payload_t *tp, uint8_t need)
{
    if (!tp) return;
    if (need > SSH_MAX_TYPED_BOOL_FIELDS) need = SSH_MAX_TYPED_BOOL_FIELDS;
    if (tp->boolean_count < need) tp->boolean_count = need;
    if (tp->boolean_count > SSH_MAX_TYPED_BOOL_FIELDS)
        tp->boolean_count = SSH_MAX_TYPED_BOOL_FIELDS;
    fix_bool_value(&tp->boolean_value);
    for (uint8_t i = 0; i < tp->boolean_count; ++i)
        fix_bool_value(&tp->boolean_values[i]);
}

static void fix_typed_uint32_count(ssh_typed_payload_t *tp, uint8_t need)
{
    if (!tp) return;
    if (need > SSH_MAX_TYPED_UINT32_FIELDS) need = SSH_MAX_TYPED_UINT32_FIELDS;
    if (tp->uint32_count < need) tp->uint32_count = need;
    if (tp->uint32_count > SSH_MAX_TYPED_UINT32_FIELDS)
        tp->uint32_count = SSH_MAX_TYPED_UINT32_FIELDS;
}

static void fix_typed_string_count(ssh_typed_payload_t *tp, uint8_t need)
{
    if (!tp) return;
    if (need > SSH_MAX_TYPED_STRING_FIELDS) need = SSH_MAX_TYPED_STRING_FIELDS;
    if (tp->string_count < need) tp->string_count = need;
    if (tp->string_count > SSH_MAX_TYPED_STRING_FIELDS)
        tp->string_count = SSH_MAX_TYPED_STRING_FIELDS;
}

static void fix_string_bound(ssh_string_field_t *f)
{
    if (f && f->len > SSH_MAX_TYPED_FIELD_BYTES)
        f->len = SSH_MAX_TYPED_FIELD_BYTES;
}

static void fix_field_default(ssh_string_field_t *f, const char *lit)
{
    fix_string_bound(f);
    if (f && f->len == 0) set_field(f, lit);
}

static void fix_ascii_string_or_default(ssh_string_field_t *f, const char *lit, int allow_space)
{
    if (!f) return;
    fix_string_bound(f);
    if (f->len == 0) { set_field(f, lit); return; }
    for (uint32_t i = 0; i < f->len; ++i) {
        unsigned char c = f->bytes[i];
        if (c == 0 || c == '\r' || c == '\n' || c > 0x7e || (!allow_space && c <= 0x20)) {
            set_field(f, lit);
            return;
        }
    }
}

static void fix_namelist_field(ssh_string_field_t *f, const char *fallback, int allow_empty)
{
    if (!f) return;
    fix_string_bound(f);
    if (allow_empty && f->len == 0) return;
    if (!namelist_looks_valid(f->bytes, f->len)) set_field(f, fallback);
}

static void fix_port_u32(uint32_t *v, uint32_t fallback)
{
    if (!v) return;
    if (*v > 65535u) *v %= 65536u;
    if (*v == 0 && fallback) *v = fallback;
}

static void fix_nonzero_u32(uint32_t *v, uint32_t fallback)
{
    if (v && *v == 0) *v = fallback ? fallback : 1u;
}

static void fix_channel_window(uint32_t *v)
{
    fix_nonzero_u32(v, 65536u);
}

static void fix_channel_packet_size(uint32_t *v)
{
    fix_nonzero_u32(v, 32768u);
}

static void fix_mpint_field(ssh_string_field_t *f, const unsigned char *fallback, uint32_t fallback_len)
{
    if (!f) return;
    fix_string_bound(f);
    if (f->len == 0) {
        if (fallback && fallback_len) {
            if (fallback_len > SSH_MAX_TYPED_FIELD_BYTES) fallback_len = SSH_MAX_TYPED_FIELD_BYTES;
            memcpy(f->bytes, fallback, fallback_len);
            f->len = fallback_len;
        } else {
            f->bytes[0] = 1;
            f->len = 1;
        }
        return;
    }
    /* RFC4251 mpint is two's-complement, minimal length. For client KEX values
     * we keep it positive and non-zero so OpenSSH reaches deeper KEX checks. */
    while (f->len > 1 && f->bytes[0] == 0 && (f->bytes[1] & 0x80u) == 0) {
        memmove(f->bytes, f->bytes + 1, f->len - 1);
        f->len--;
    }
    if (f->len == 1 && f->bytes[0] == 0) f->bytes[0] = 1;
    if (f->bytes[0] & 0x80u) {
        if (f->len < SSH_MAX_TYPED_FIELD_BYTES) {
            memmove(f->bytes + 1, f->bytes, f->len);
            f->bytes[0] = 0;
            f->len++;
        } else {
            f->bytes[0] &= 0x7fu;
            if (f->bytes[0] == 0) f->bytes[0] = 1;
        }
    }
}

static void fix_hostkey_algorithm_field(ssh_string_field_t *f)
{
    fix_namelist_field(f, "ssh-rsa", 0);
}

static int ssh_valid_channel_type(const ssh_string_field_t *f)
{
    return f && (ssh_field_is(f, "session") || ssh_field_is(f, "x11") ||
                 ssh_field_is(f, "direct-tcpip") || ssh_field_is(f, "forwarded-tcpip"));
}

static int ssh_valid_channel_request_type(const ssh_string_field_t *f)
{
    return f && (ssh_field_is(f, "pty-req") || ssh_field_is(f, "x11-req") ||
                 ssh_field_is(f, "env") || ssh_field_is(f, "shell") ||
                 ssh_field_is(f, "exec") || ssh_field_is(f, "subsystem") ||
                 ssh_field_is(f, "window-change") || ssh_field_is(f, "xon-xoff") ||
                 ssh_field_is(f, "signal") || ssh_field_is(f, "exit-status") ||
                 ssh_field_is(f, "exit-signal"));
}

static void clear_unused_typed_tail(ssh_typed_payload_t *tp)
{
    if (!tp) return;
    /* For RFC-schema messages, reassembler derives payload from structured
     * fields. Keeping arbitrary trailing payload often creates messages that
     * parse but fail the receiver's stricter state machine. */
    tp->trailing_payload.len = 0;
}

static unsigned char ssh_default_message_code(ssh_packet_type_t type)
{
    switch (type)
    {
    case SSH_DISCONNECT: return SSH_MSG_DISCONNECT;
    case SSH_IGNORE: return SSH_MSG_IGNORE;
    case SSH_UNIMPLEMENTED: return SSH_MSG_UNIMPLEMENTED;
    case SSH_DEBUG: return SSH_MSG_DEBUG;
    case SSH_SERVICE_ACCEPT: return SSH_MSG_SERVICE_ACCEPT;
    case SSH_KEXDH_REPLY: return SSH_MSG_KEXDH_REPLY;
    case SSH_KEX_DH_GEX_INIT: return SSH_MSG_KEX_DH_GEX_INIT;
    case SSH_KEX_DH_GEX_REQUEST: return SSH_MSG_KEX_DH_GEX_REQUEST;
    case SSH_USERAUTH_INFO_RESPONSE: return SSH_MSG_USERAUTH_INFO_RESPONSE;
    case SSH_USERAUTH_REQUEST: return SSH_MSG_USERAUTH_REQUEST;
    case SSH_USERAUTH_FAILURE: return SSH_MSG_USERAUTH_FAILURE;
    case SSH_USERAUTH_SUCCESS: return SSH_MSG_USERAUTH_SUCCESS;
    case SSH_USERAUTH_BANNER: return SSH_MSG_USERAUTH_BANNER;
    case SSH_USERAUTH_METHOD_REPLY: return SSH_MSG_USERAUTH_METHOD_REPLY;
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
    default: return 0;
    }
}

static void fix_typed(ssh_packet_type_t type, ssh_typed_payload_t *tp)
{
    if (!tp) return;
    if (tp->payload_len > SSH_MAX_TYPED_PAYLOAD_BYTES)
        tp->payload_len = SSH_MAX_TYPED_PAYLOAD_BYTES;
    unsigned char def = ssh_default_message_code(type);
    if (def) tp->message_code = def;
    if (def && tp->field_schema == 0) tp->field_schema = def;
    if (tp->field_schema != tp->message_code && tp->message_code != 0)
        tp->field_schema = tp->message_code;

    fix_typed_uint32_count(tp, 0);
    fix_typed_string_count(tp, 0);
    fix_typed_boolean_count(tp, 0);
    for (unsigned i = 0; i < SSH_MAX_TYPED_STRING_FIELDS; i++)
        fix_string_bound(&tp->strings[i]);
    if (tp->trailing_payload.len > SSH_MAX_TYPED_FIELD_BYTES)
        tp->trailing_payload.len = SSH_MAX_TYPED_FIELD_BYTES;

    if (!tp->field_schema) return;
    clear_unused_typed_tail(tp);

    switch (tp->field_schema) {
    case SSH_MSG_DISCONNECT:
        /* uint32 reason_code; string description; string language_tag */
        fix_typed_uint32_count(tp, 1);
        if (tp->uint32_values[0] == 0 || tp->uint32_values[0] > 15) tp->uint32_values[0] = 11;
        fix_typed_string_count(tp, 2);
        fix_ascii_string_or_default(&tp->strings[0], "lemur disconnect", 1);
        fix_namelist_field(&tp->strings[1], "en", 1);
        break;
    case SSH_MSG_IGNORE:
        /* string data */
        fix_typed_string_count(tp, 1);
        fix_field_default(&tp->strings[0], "ignore");
        break;
    case SSH_MSG_UNIMPLEMENTED:
        /* uint32 packet_sequence_number */
        fix_typed_uint32_count(tp, 1);
        break;
    case SSH_MSG_DEBUG:
        /* boolean always_display; string message; string language_tag */
        fix_typed_boolean_count(tp, 1);
        fix_typed_string_count(tp, 2);
        fix_ascii_string_or_default(&tp->strings[0], "debug", 1);
        fix_namelist_field(&tp->strings[1], "en", 1);
        break;
    case SSH_MSG_SERVICE_ACCEPT:
        /* string service_name */
        fix_typed_string_count(tp, 1);
        if (!ssh_valid_service_name(&tp->strings[0])) set_field(&tp->strings[0], "ssh-userauth");
        break;
    case SSH_MSG_KEXDH_REPLY: {
        /* string server_public_host_key; mpint f; string signature */
        static const unsigned char one[] = {1};
        fix_typed_string_count(tp, 3);
        fix_field_default(&tp->strings[0], "ssh-rsa");
        fix_mpint_field(&tp->strings[1], one, sizeof(one));
        fix_field_default(&tp->strings[2], "sig");
        break;
    }
    case SSH_MSG_KEX_DH_GEX_INIT: {
        /* mpint e */
        static const unsigned char gex_e[] = {2};
        fix_typed_string_count(tp, 1);
        fix_mpint_field(&tp->strings[0], gex_e, sizeof(gex_e));
        break;
    }
    case SSH_MSG_KEX_DH_GEX_REQUEST:
        /* uint32 min; uint32 n; uint32 max, with min <= n <= max. */
        fix_typed_uint32_count(tp, 3);
        if (tp->uint32_values[0] < 1024) tp->uint32_values[0] = 1024;
        if (tp->uint32_values[2] < tp->uint32_values[0]) tp->uint32_values[2] = tp->uint32_values[0];
        if (tp->uint32_values[1] < tp->uint32_values[0]) tp->uint32_values[1] = tp->uint32_values[0];
        if (tp->uint32_values[1] > tp->uint32_values[2]) tp->uint32_values[1] = tp->uint32_values[2];
        break;
    case SSH_MSG_USERAUTH_REQUEST:
        /* string user; string service; string method; method-specific fields. */
        fix_typed_string_count(tp, 3);
        fix_ascii_string_or_default(&tp->strings[0], "ubuntu", 0);
        set_field(&tp->strings[1], "ssh-connection");
        if (!ssh_valid_userauth_method(&tp->strings[2])) set_field(&tp->strings[2], "none");
        if (ssh_field_is(&tp->strings[2], "publickey")) {
            fix_typed_boolean_count(tp, 1);
            fix_typed_string_count(tp, tp->boolean_value ? 6 : 5);
            fix_hostkey_algorithm_field(&tp->strings[3]);
            fix_field_default(&tp->strings[4], "keyblob");
            if (tp->boolean_value) fix_field_default(&tp->strings[5], "sig");
        } else if (ssh_field_is(&tp->strings[2], "password")) {
            fix_typed_boolean_count(tp, 1);
            fix_typed_string_count(tp, tp->boolean_value ? 5 : 4);
            fix_ascii_string_or_default(&tp->strings[3], "ubuntu", 1);
            if (tp->boolean_value) fix_ascii_string_or_default(&tp->strings[4], "ubuntu", 1);
        } else if (ssh_field_is(&tp->strings[2], "hostbased")) {
            fix_typed_string_count(tp, 8);
            fix_hostkey_algorithm_field(&tp->strings[3]);
            fix_field_default(&tp->strings[4], "keyblob");
            fix_ascii_string_or_default(&tp->strings[5], "client.example", 0);
            fix_ascii_string_or_default(&tp->strings[6], "ubuntu", 0);
            fix_field_default(&tp->strings[7], "sig");
        } else if (ssh_field_is(&tp->strings[2], "keyboard-interactive")) {
            fix_typed_string_count(tp, 5);
            fix_namelist_field(&tp->strings[3], "", 1);
            fix_namelist_field(&tp->strings[4], "", 1);
        }
        break;
    case SSH_MSG_USERAUTH_FAILURE:
        /* name-list auths_that_can_continue; boolean partial_success */
        fix_typed_string_count(tp, 1);
        fix_namelist_field(&tp->strings[0], "publickey,password,keyboard-interactive,none", 0);
        fix_typed_boolean_count(tp, 1);
        break;
    case SSH_MSG_USERAUTH_SUCCESS:
        break;
    case SSH_MSG_USERAUTH_BANNER:
        /* string message; string language_tag */
        fix_typed_string_count(tp, 2);
        fix_ascii_string_or_default(&tp->strings[0], "banner", 1);
        fix_namelist_field(&tp->strings[1], "en", 1);
        break;
    case SSH_MSG_USERAUTH_METHOD_REPLY:
        /* RFC4252 overload for PK_OK: string algorithm; string public_key_blob. */
        fix_typed_string_count(tp, 2);
        fix_hostkey_algorithm_field(&tp->strings[0]);
        fix_field_default(&tp->strings[1], "keyblob");
        break;
    case SSH_MSG_USERAUTH_INFO_RESPONSE:
        /* uint32 num-responses; string responses[num-responses]. */
        if (tp->string_count > SSH_MAX_TYPED_STRING_FIELDS) tp->string_count = SSH_MAX_TYPED_STRING_FIELDS;
        fix_typed_uint32_count(tp, 1);
        tp->uint32_values[0] = tp->string_count;
        for (uint8_t i = 0; i < tp->string_count; ++i)
            fix_string_bound(&tp->strings[i]);
        break;
    case SSH_MSG_GLOBAL_REQUEST:
        /* string request_name; boolean want_reply; optional request-specific fields. */
        fix_typed_string_count(tp, 1);
        fix_typed_boolean_count(tp, 1);
        if (tp->strings[0].len == 0 || !namelist_looks_valid(tp->strings[0].bytes, tp->strings[0].len))
            set_field(&tp->strings[0], "tcpip-forward");
        if (ssh_field_is(&tp->strings[0], "tcpip-forward") || ssh_field_is(&tp->strings[0], "cancel-tcpip-forward")) {
            fix_typed_string_count(tp, 2);
            fix_typed_uint32_count(tp, 1);
            fix_ascii_string_or_default(&tp->strings[1], "127.0.0.1", 0);
            fix_port_u32(&tp->uint32_values[0], 2222);
        }
        break;
    case SSH_MSG_REQUEST_SUCCESS:
    case SSH_MSG_REQUEST_FAILURE:
        break;
    case SSH_MSG_CHANNEL_OPEN:
        /* string channel_type; uint32 sender; uint32 window; uint32 max_packet; type-specific fields. */
        fix_typed_string_count(tp, 1);
        if (!ssh_valid_channel_type(&tp->strings[0])) set_field(&tp->strings[0], "session");
        fix_typed_uint32_count(tp, 3);
        fix_channel_window(&tp->uint32_values[1]);
        fix_channel_packet_size(&tp->uint32_values[2]);
        if (ssh_field_is(&tp->strings[0], "x11")) {
            fix_typed_string_count(tp, 2);
            fix_typed_uint32_count(tp, 4);
            fix_ascii_string_or_default(&tp->strings[1], "127.0.0.1", 0);
            fix_port_u32(&tp->uint32_values[3], 6000);
        } else if (ssh_field_is(&tp->strings[0], "direct-tcpip") || ssh_field_is(&tp->strings[0], "forwarded-tcpip")) {
            fix_typed_string_count(tp, 3);
            fix_typed_uint32_count(tp, 5);
            fix_ascii_string_or_default(&tp->strings[1], "127.0.0.1", 0);
            fix_port_u32(&tp->uint32_values[3], 22);
            fix_ascii_string_or_default(&tp->strings[2], "127.0.0.1", 0);
            fix_port_u32(&tp->uint32_values[4], 49152);
        }
        break;
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        /* recipient; sender; initial_window_size; maximum_packet_size */
        fix_typed_uint32_count(tp, 4);
        fix_channel_window(&tp->uint32_values[2]);
        fix_channel_packet_size(&tp->uint32_values[3]);
        break;
    case SSH_MSG_CHANNEL_OPEN_FAILURE:
        /* recipient; reason_code; description; language_tag */
        fix_typed_uint32_count(tp, 2);
        if (tp->uint32_values[1] < 1 || tp->uint32_values[1] > 4) tp->uint32_values[1] = 2;
        fix_typed_string_count(tp, 2);
        fix_ascii_string_or_default(&tp->strings[0], "open failed", 1);
        fix_namelist_field(&tp->strings[1], "en", 1);
        break;
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        /* recipient; bytes_to_add */
        fix_typed_uint32_count(tp, 2);
        fix_nonzero_u32(&tp->uint32_values[1], 32768u);
        break;
    case SSH_MSG_CHANNEL_DATA:
        /* recipient; string data */
        fix_typed_uint32_count(tp, 1);
        fix_typed_string_count(tp, 1);
        fix_field_default(&tp->strings[0], "data");
        break;
    case SSH_MSG_CHANNEL_EXTENDED_DATA:
        /* recipient; data_type_code; string data. RFC4254 defines stderr as 1. */
        fix_typed_uint32_count(tp, 2);
        if (tp->uint32_values[1] == 0) tp->uint32_values[1] = 1;
        fix_typed_string_count(tp, 1);
        fix_field_default(&tp->strings[0], "stderr");
        break;
    case SSH_MSG_CHANNEL_EOF:
    case SSH_MSG_CHANNEL_CLOSE:
    case SSH_MSG_CHANNEL_SUCCESS:
    case SSH_MSG_CHANNEL_FAILURE:
        /* recipient */
        fix_typed_uint32_count(tp, 1);
        break;
    case SSH_MSG_CHANNEL_REQUEST:
        /* recipient; string request_type; boolean want_reply; request-specific fields. */
        fix_typed_uint32_count(tp, 1);
        fix_typed_string_count(tp, 1);
        fix_typed_boolean_count(tp, 1);
        if (!ssh_valid_channel_request_type(&tp->strings[0])) set_field(&tp->strings[0], "exec");
        if (ssh_field_is(&tp->strings[0], "pty-req")) {
            fix_typed_string_count(tp, 3);
            fix_typed_uint32_count(tp, 5);
            fix_ascii_string_or_default(&tp->strings[1], "xterm", 0);
            fix_nonzero_u32(&tp->uint32_values[1], 80);
            fix_nonzero_u32(&tp->uint32_values[2], 24);
            fix_nonzero_u32(&tp->uint32_values[3], 640);
            fix_nonzero_u32(&tp->uint32_values[4], 480);
            fix_string_bound(&tp->strings[2]);
        } else if (ssh_field_is(&tp->strings[0], "x11-req")) {
            fix_typed_boolean_count(tp, 2);
            fix_typed_string_count(tp, 3);
            fix_typed_uint32_count(tp, 2);
            fix_namelist_field(&tp->strings[1], "MIT-MAGIC-COOKIE-1", 0);
            fix_field_default(&tp->strings[2], "0123456789abcdef0123456789abcdef");
            fix_port_u32(&tp->uint32_values[1], 0);
        } else if (ssh_field_is(&tp->strings[0], "env")) {
            fix_typed_string_count(tp, 3);
            fix_ascii_string_or_default(&tp->strings[1], "LANG", 0);
            fix_ascii_string_or_default(&tp->strings[2], "C", 1);
        } else if (ssh_field_is(&tp->strings[0], "shell")) {
            /* no extra fields */
        } else if (ssh_field_is(&tp->strings[0], "exec") || ssh_field_is(&tp->strings[0], "subsystem") ||
                   ssh_field_is(&tp->strings[0], "signal")) {
            fix_typed_string_count(tp, 2);
            fix_ascii_string_or_default(&tp->strings[1],
                ssh_field_is(&tp->strings[0], "subsystem") ? "sftp" :
                ssh_field_is(&tp->strings[0], "signal") ? "TERM" : "id", 1);
        } else if (ssh_field_is(&tp->strings[0], "window-change")) {
            fix_typed_uint32_count(tp, 5);
            fix_nonzero_u32(&tp->uint32_values[1], 80);
            fix_nonzero_u32(&tp->uint32_values[2], 24);
            fix_nonzero_u32(&tp->uint32_values[3], 640);
            fix_nonzero_u32(&tp->uint32_values[4], 480);
        } else if (ssh_field_is(&tp->strings[0], "xon-xoff")) {
            fix_typed_boolean_count(tp, 2);
        } else if (ssh_field_is(&tp->strings[0], "exit-status")) {
            fix_typed_uint32_count(tp, 2);
        } else if (ssh_field_is(&tp->strings[0], "exit-signal")) {
            fix_typed_boolean_count(tp, 2);
            fix_typed_string_count(tp, 4);
            fix_namelist_field(&tp->strings[1], "TERM", 0);
            fix_ascii_string_or_default(&tp->strings[2], "exit", 1);
            fix_namelist_field(&tp->strings[3], "en", 1);
        }
        break;
    default:
        tp->field_schema = 0;
        break;
    }
}

static void fix_banner(ssh_banner_t *b)
{
    memcpy(b->proto_id, "SSH", 3);
    b->dash1 = '-';
    memcpy(b->protoversion, "2.0", 3);
    b->dash2 = '-';
    b->cr = '\r';
    b->lf = '\n';

    if (b->software_len >= SSH_MAX_BANNER_LEN)
    {
        b->software_len = SSH_MAX_BANNER_LEN - 1;
    }
    if (b->comments_len >= SSH_MAX_BANNER_LEN)
    {
        b->comments_len = SSH_MAX_BANNER_LEN - 1;
    }
    if (!b->has_comments)
    {
        b->comments_len = 0;
    }
    if (b->raw_len > SSH_MAX_BANNER_LEN)
    {
        b->raw_len = SSH_MAX_BANNER_LEN;
    }
    if (b->raw_len) {
        if (b->raw_len < 10 ||
            memcmp(b->raw, "SSH-2.0-", 8) != 0 ||
            b->raw[b->raw_len - 1] != '\n') {
            b->raw_len = 0;
        }
    }
    if (b->raw_len >= 2)
    {
        b->raw[b->raw_len - 2] = '\r';
        b->raw[b->raw_len - 1] = '\n';
    }
}

static void fix_transport(ssh_transport_packet_t *t)
{
    uint32_t max_payload = SSH_MAX_WIRE_PACKET_BYTES - 1u - SSH_MAX_PADDING_BYTES;
    if (t->payload_len > max_payload)
    {
        t->payload_len = max_payload;
    }
    if (t->has_message_code)
    {
        if (t->payload_len == 0)
        {
            t->payload_len = 1;
        }
        t->payload[0] = t->message_code;
    }
    else if (t->payload_len > 0)
    {
        t->message_code = t->payload[0];
    }
    t->padding_length = (uint8_t)ssh_padding_for_payload(t->payload_len);
    t->packet_length = 1u + t->payload_len + (uint32_t)t->padding_length;
}

static void fix_kexinit(ssh_kexinit_t *k)
{
    k->message_code = SSH_MSG_KEXINIT;
    if (k->kex_algorithms_len > SSH_MAX_NAMELIST_BYTES)
        k->kex_algorithms_len = SSH_MAX_NAMELIST_BYTES;
    if (k->server_host_key_algorithms_len > SSH_MAX_NAMELIST_BYTES)
        k->server_host_key_algorithms_len = SSH_MAX_NAMELIST_BYTES;
    if (k->encryption_algorithms_client_to_server_len > SSH_MAX_NAMELIST_BYTES)
        k->encryption_algorithms_client_to_server_len = SSH_MAX_NAMELIST_BYTES;
    if (k->encryption_algorithms_server_to_client_len > SSH_MAX_NAMELIST_BYTES)
        k->encryption_algorithms_server_to_client_len = SSH_MAX_NAMELIST_BYTES;
    if (k->mac_algorithms_client_to_server_len > SSH_MAX_NAMELIST_BYTES)
        k->mac_algorithms_client_to_server_len = SSH_MAX_NAMELIST_BYTES;
    if (k->mac_algorithms_server_to_client_len > SSH_MAX_NAMELIST_BYTES)
        k->mac_algorithms_server_to_client_len = SSH_MAX_NAMELIST_BYTES;
    if (k->compression_algorithms_client_to_server_len > SSH_MAX_NAMELIST_BYTES)
        k->compression_algorithms_client_to_server_len = SSH_MAX_NAMELIST_BYTES;
    if (k->compression_algorithms_server_to_client_len > SSH_MAX_NAMELIST_BYTES)
        k->compression_algorithms_server_to_client_len = SSH_MAX_NAMELIST_BYTES;
    if (k->languages_client_to_server_len > SSH_MAX_NAMELIST_BYTES)
        k->languages_client_to_server_len = SSH_MAX_NAMELIST_BYTES;
    if (k->languages_server_to_client_len > SSH_MAX_NAMELIST_BYTES)
        k->languages_server_to_client_len = SSH_MAX_NAMELIST_BYTES;
    if (!namelist_looks_valid(k->kex_algorithms, k->kex_algorithms_len))
        set_bytes(k->kex_algorithms, &k->kex_algorithms_len, SSH_MAX_NAMELIST_BYTES,
                  "curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1");
    if (!namelist_looks_valid(k->server_host_key_algorithms, k->server_host_key_algorithms_len))
        set_bytes(k->server_host_key_algorithms, &k->server_host_key_algorithms_len, SSH_MAX_NAMELIST_BYTES,
                  "rsa-sha2-256,rsa-sha2-512,ssh-rsa");
    /* The replay target intentionally uses a plaintext cipher and a fixed
     * ETM MAC.  Always canonicalize these fields, including when the input
     * contains a syntactically valid AES/ChaCha/HMAC proposal: merely checking
     * namelist syntax is insufficient because the target would reject a
     * proposal with no common algorithm and the semantic reassembler cannot
     * produce encrypted follow-up packets. */
    set_bytes(k->encryption_algorithms_client_to_server,
              &k->encryption_algorithms_client_to_server_len,
              SSH_MAX_NAMELIST_BYTES, "none");
    set_bytes(k->encryption_algorithms_server_to_client,
              &k->encryption_algorithms_server_to_client_len,
              SSH_MAX_NAMELIST_BYTES, "none");
    set_bytes(k->mac_algorithms_client_to_server,
              &k->mac_algorithms_client_to_server_len,
              SSH_MAX_NAMELIST_BYTES, "umac-64-etm@openssh.com");
    set_bytes(k->mac_algorithms_server_to_client,
              &k->mac_algorithms_server_to_client_len,
              SSH_MAX_NAMELIST_BYTES, "umac-64-etm@openssh.com");
    if (!namelist_looks_valid(k->compression_algorithms_client_to_server, k->compression_algorithms_client_to_server_len))
        set_bytes(k->compression_algorithms_client_to_server, &k->compression_algorithms_client_to_server_len,
                  SSH_MAX_NAMELIST_BYTES, "none");
    if (!namelist_looks_valid(k->compression_algorithms_server_to_client, k->compression_algorithms_server_to_client_len))
        set_bytes(k->compression_algorithms_server_to_client, &k->compression_algorithms_server_to_client_len,
                  SSH_MAX_NAMELIST_BYTES, "none");
    if (k->languages_client_to_server_len > 0 &&
        !namelist_looks_valid(k->languages_client_to_server, k->languages_client_to_server_len))
        k->languages_client_to_server_len = 0;
    if (k->languages_server_to_client_len > 0 &&
        !namelist_looks_valid(k->languages_server_to_client, k->languages_server_to_client_len))
        k->languages_server_to_client_len = 0;
    k->first_kex_packet_follows = 0;
    k->reserved_zero = 0;
}

// [RFC4253-4.2] Identification string is SSH-protoversion-softwareversion SP comments CR LF;
// server fuzzing uses SSH-2.0 and bounded lines.
void fix_RFC4253_4_2_identification_string(ssh_banner_t *b) { fix_banner(b); }

// [RFC4253-6] Binary packet protocol: packet_length = payload + padding_length + 1,
// padding_length >= 4, and packet_length + 4 is a multiple of the cipher block size (8 here).
void fix_RFC4253_6_binary_packet_length_padding(ssh_transport_packet_t *t) { fix_transport(t); }

// [RFC4253-7.1] KEXINIT has ten name-lists, a boolean first_kex_packet_follows,
// and a uint32 reserved field that MUST be zero.
void fix_RFC4253_7_1_kexinit_namelists_and_reserved(ssh_kexinit_t *k) { fix_kexinit(k); }

// [RFC4251-5, RFC4252, RFC4254] Structured strings/booleans/uint32 fields are
// length-delimited, bounded, and schema-compatible with the message number.
void fix_RFC4251_5_typed_payload_fields(ssh_packet_type_t type, ssh_typed_payload_t *tp) { fix_typed(type, tp); }

// [RFC4253-8] SSH_MSG_KEXDH_INIT has message number 30 followed by one mpint e.
void fix_RFC4253_8_kexdh_init_mpint(ssh_kexdh_init_t *d)
{
    if (!d) return;
    d->message_code = SSH_MSG_KEXDH_INIT;
    if (d->e_len > SSH_MAX_MPINT_BYTES) d->e_len = SSH_MAX_MPINT_BYTES;
    if (d->e_len == 0) { d->e[0] = 1; d->e_len = 1; }
}


static int ssh_kexinit_prefers_gex(const ssh_kexinit_t *k)
{
    static const char gex[] = "diffie-hellman-group-exchange-";
    if (!k) return 0;
    uint32_t n = k->kex_algorithms_len;
    if (n > SSH_MAX_NAMELIST_BYTES) n = SSH_MAX_NAMELIST_BYTES;
    uint32_t glen = (uint32_t)(sizeof(gex) - 1u);
    if (n < glen) return 0;
    return memcmp(k->kex_algorithms, gex, glen) == 0;
}

static void ssh_fix_set_gex_request(ssh_packet_t *p)
{
    if (!p) return;
    memset(&p->u.typed, 0, sizeof(p->u.typed));
    p->type = SSH_KEX_DH_GEX_REQUEST;
    p->wire_len = 0;
    p->has_transport_padding = 0;
    p->transport_padding_length = 0;
    p->transport_payload_length = 0;
    p->u.typed.message_code = SSH_MSG_KEX_DH_GEX_REQUEST;
    p->u.typed.field_schema = SSH_MSG_KEX_DH_GEX_REQUEST;
    p->u.typed.uint32_count = 3;
    p->u.typed.uint32_values[0] = 1024;
    p->u.typed.uint32_values[1] = 2048;
    p->u.typed.uint32_values[2] = 8192;
}

static void ssh_fix_set_kexdh_init(ssh_packet_t *p)
{
    if (!p) return;
    memset(&p->u.kexdh_init, 0, sizeof(p->u.kexdh_init));
    p->type = SSH_KEXDH_INIT;
    p->wire_len = 0;
    p->has_transport_padding = 0;
    p->transport_padding_length = 0;
    p->transport_payload_length = 0;
    p->u.kexdh_init.message_code = SSH_MSG_KEXDH_INIT;
    p->u.kexdh_init.e_len = 1;
    p->u.kexdh_init.e[0] = 1;
}

static int ssh_is_client_kex_payload_type(ssh_packet_type_t type)
{
    return type == SSH_KEXDH_INIT ||
           type == SSH_KEX_DH_GEX_REQUEST ||
           type == SSH_KEX_DH_GEX_INIT;
}

// [RFC4253-10] SERVICE_REQUEST has message number 5 and a service name string.
void fix_RFC4253_10_service_request_name(ssh_service_request_t *s)
{
    if (!s) return;
    s->message_code = SSH_MSG_SERVICE_REQUEST;
    if (s->service_name_len > SSH_MAX_SERVICE_NAME_BYTES)
        s->service_name_len = SSH_MAX_SERVICE_NAME_BYTES;
    if (!string_eq(s->service_name, s->service_name_len, "ssh-userauth") &&
        !string_eq(s->service_name, s->service_name_len, "ssh-connection"))
        set_bytes(s->service_name, &s->service_name_len,
                  SSH_MAX_SERVICE_NAME_BYTES, "ssh-userauth");
}

// [RFC4253-7.3] SSH_MSG_NEWKEYS has message number 21 and no fields.
void fix_RFC4253_7_3_newkeys_message(ssh_newkeys_t *n)
{
    if (!n) return;
    n->message_code = SSH_MSG_NEWKEYS;
}

static unsigned char ssh_message_code_from_packet(const ssh_packet_t *p)
{
    if (!p) return 0;
    switch (p->type) {
    case SSH_BANNER: return 0;
    case SSH_TRANSPORT_PACKET:
        if (p->u.transport.has_message_code) return p->u.transport.message_code;
        if (p->u.transport.payload_len) return p->u.transport.payload[0];
        return 0;
    case SSH_KEXINIT: return SSH_MSG_KEXINIT;
    case SSH_KEXDH_INIT: return SSH_MSG_KEXDH_INIT;
    case SSH_SERVICE_REQUEST: return SSH_MSG_SERVICE_REQUEST;
    case SSH_NEWKEYS: return SSH_MSG_NEWKEYS;
    case SSH_DISCONNECT:
    case SSH_IGNORE:
    case SSH_UNIMPLEMENTED:
    case SSH_DEBUG:
    case SSH_SERVICE_ACCEPT:
    case SSH_KEXDH_REPLY:
    case SSH_KEX_DH_GEX_INIT:
    case SSH_KEX_DH_GEX_REQUEST:
    case SSH_USERAUTH_INFO_RESPONSE:
    case SSH_USERAUTH_REQUEST:
    case SSH_USERAUTH_FAILURE:
    case SSH_USERAUTH_SUCCESS:
    case SSH_USERAUTH_BANNER:
    case SSH_USERAUTH_METHOD_REPLY:
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
        return p->u.typed.message_code ? p->u.typed.message_code : ssh_default_message_code(p->type);
    default:
        return 0;
    }
}

static int ssh_packet_is_server_to_client(const ssh_packet_t *p)
{
    if (!p) return 0;
    switch (p->type) {
    case SSH_SERVICE_ACCEPT:
    case SSH_KEXDH_REPLY:
    case SSH_USERAUTH_FAILURE:
    case SSH_USERAUTH_SUCCESS:
    case SSH_USERAUTH_BANNER:
    case SSH_USERAUTH_METHOD_REPLY:
    case SSH_REQUEST_SUCCESS:
    case SSH_REQUEST_FAILURE:
    case SSH_CHANNEL_OPEN_CONFIRMATION:
    case SSH_CHANNEL_OPEN_FAILURE:
    case SSH_CHANNEL_SUCCESS:
    case SSH_CHANNEL_FAILURE:
        return 1;
    default:
        return 0;
    }
}

static int ssh_packet_is_channel_message(const ssh_packet_t *p)
{
    if (!p) return 0;
    return p->type == SSH_CHANNEL_OPEN ||
           p->type == SSH_CHANNEL_WINDOW_ADJUST ||
           p->type == SSH_CHANNEL_DATA ||
           p->type == SSH_CHANNEL_EXTENDED_DATA ||
           p->type == SSH_CHANNEL_EOF ||
           p->type == SSH_CHANNEL_CLOSE ||
           p->type == SSH_CHANNEL_REQUEST ||
           p->type == SSH_CHANNEL_OPEN_CONFIRMATION ||
           p->type == SSH_CHANNEL_OPEN_FAILURE ||
           p->type == SSH_CHANNEL_SUCCESS ||
           p->type == SSH_CHANNEL_FAILURE;
}

static void ssh_drop_packet(ssh_packet_t *p)
{
    if (!p) return;
    p->type = SSH_OPAQUE;
    p->wire_len = 0;
    p->has_transport_padding = 0;
    p->transport_padding_length = 0;
    p->transport_payload_length = 0;
    memset(&p->u.opaque, 0, sizeof(p->u.opaque));
}

static void ssh_fix_sequence_constraints(ssh_packet_t *pkt, int num_packets)
{
    if (!pkt || num_packets <= 1)
        return;

    int saw_binary = 0;
    int saw_kexinit = 0;
    int kex_requires_gex_request = 0;
    int saw_kex_payload = 0;
    int saw_service_request = 0;
    int saw_userauth = 0;
    int saw_channel_open = 0;
    int after_newkeys = 0;
    uint32_t client_channel = 0;

    for (int i = 0; i < num_packets; ++i) {
        unsigned char code = ssh_message_code_from_packet(&pkt[i]);

        if (after_newkeys) {
            /*
             * After SSH_MSG_NEWKEYS the peer switches to encrypted packets.
             * Preserve opaque bytes from real seeds because they may still be
             * valid ciphertext for this deterministic ProFuzzBench OpenSSH
             * build. Drop only cleartext semantic packets that Lemur cannot
             * encrypt consistently.
             */
            if (pkt[i].type != SSH_OPAQUE)
                ssh_drop_packet(&pkt[i]);
            continue;
        }

        if (pkt[i].type == SSH_BANNER) {
            if (saw_binary) {
                ssh_drop_packet(&pkt[i]);
                continue;
            }
        } else {
            saw_binary = 1;
        }

        if (ssh_packet_is_server_to_client(&pkt[i])) {
            /*
             * ProFuzzBench drives the OpenSSH server with client-side input.
             * Server-to-client packets in the client stream are only useful as
             * raw AFL mutations; semantic regeneration should not emit them.
             */
            ssh_drop_packet(&pkt[i]);
            continue;
        }

        if (pkt[i].type != SSH_TRANSPORT_PACKET &&
            (code == SSH_MSG_KEXDH_INIT || code == SSH_MSG_KEX_DH_GEX_INIT ||
             code == SSH_MSG_KEX_DH_GEX_REQUEST) && !saw_kexinit) {
            ssh_drop_packet(&pkt[i]);
            continue;
        }

        if (pkt[i].type == SSH_KEXINIT) {
            saw_kexinit = 1;
            kex_requires_gex_request = ssh_kexinit_prefers_gex(&pkt[i].u.kexinit);
        } else if (pkt[i].type != SSH_TRANSPORT_PACKET && ssh_is_client_kex_payload_type(pkt[i].type)) {
            if (!saw_kex_payload) {
                if (kex_requires_gex_request)
                    ssh_fix_set_gex_request(&pkt[i]);
                else if (pkt[i].type != SSH_KEXDH_INIT)
                    ssh_fix_set_kexdh_init(&pkt[i]);
                saw_kex_payload = 1;
            } else {
                ssh_drop_packet(&pkt[i]);
                continue;
            }
        } else if (pkt[i].type == SSH_SERVICE_REQUEST) {
            set_bytes(pkt[i].u.service_request.service_name,
                      &pkt[i].u.service_request.service_name_len,
                      SSH_MAX_SERVICE_NAME_BYTES, "ssh-userauth");
            saw_service_request = 1;
        } else if (pkt[i].type == SSH_USERAUTH_REQUEST) {
            ssh_typed_payload_t *tp = &pkt[i].u.typed;
            if (tp->string_count < 3) tp->string_count = 3;
            if (tp->strings[0].len == 0) set_field(&tp->strings[0], "user");
            set_field(&tp->strings[1], "ssh-connection");
            if (!ssh_valid_userauth_method(&tp->strings[2]))
                set_field(&tp->strings[2], saw_service_request ? "none" : "password");
            saw_userauth = 1;
        } else if (ssh_packet_is_channel_message(&pkt[i])) {
            if (!saw_userauth) {
                ssh_drop_packet(&pkt[i]);
                continue;
            }
            if (pkt[i].type == SSH_CHANNEL_OPEN) {
                ssh_typed_payload_t *tp = &pkt[i].u.typed;
                if (tp->uint32_count < 3) tp->uint32_count = 3;
                client_channel = tp->uint32_values[0];
                saw_channel_open = 1;
            } else if (pkt[i].type != SSH_CHANNEL_OPEN && !saw_channel_open) {
                ssh_drop_packet(&pkt[i]);
                continue;
            } else if (pkt[i].type == SSH_CHANNEL_WINDOW_ADJUST ||
                       pkt[i].type == SSH_CHANNEL_DATA ||
                       pkt[i].type == SSH_CHANNEL_EXTENDED_DATA ||
                       pkt[i].type == SSH_CHANNEL_EOF ||
                       pkt[i].type == SSH_CHANNEL_CLOSE ||
                       pkt[i].type == SSH_CHANNEL_REQUEST) {
                ssh_typed_payload_t *tp = &pkt[i].u.typed;
                if (tp->uint32_count < 1) tp->uint32_count = 1;
                tp->uint32_values[0] = client_channel;
            }
        }

        if (code == SSH_MSG_NEWKEYS) {
            after_newkeys = 1;
        }
    }
}

void fix_ssh(ssh_packet_t *pkt, int num_packets)
{
    if (!pkt || num_packets <= 0)
        return;
    for (int i = 0; i < num_packets; ++i)
    {
        switch (pkt[i].type)
        {
        case SSH_BANNER:
            fix_RFC4253_4_2_identification_string(&pkt[i].u.banner);
            break;
        case SSH_TRANSPORT_PACKET:
            fix_RFC4253_6_binary_packet_length_padding(&pkt[i].u.transport);
            break;
        case SSH_KEXINIT:
            fix_RFC4253_7_1_kexinit_namelists_and_reserved(&pkt[i].u.kexinit);
            break;
        case SSH_KEXDH_INIT:
            fix_RFC4253_8_kexdh_init_mpint(&pkt[i].u.kexdh_init);
            break;
        case SSH_SERVICE_REQUEST:
            fix_RFC4253_10_service_request_name(&pkt[i].u.service_request);
            break;
        case SSH_NEWKEYS:
            fix_RFC4253_7_3_newkeys_message(&pkt[i].u.newkeys);
            break;
        case SSH_OPAQUE:
            if (pkt[i].u.opaque.len > SSH_MAX_OPAQUE_BYTES)
                pkt[i].u.opaque.len = SSH_MAX_OPAQUE_BYTES;
            break;
        case SSH_DISCONNECT:
        case SSH_IGNORE:
        case SSH_UNIMPLEMENTED:
        case SSH_DEBUG:
        case SSH_SERVICE_ACCEPT:
        case SSH_KEXDH_REPLY:
        case SSH_KEX_DH_GEX_INIT:
        case SSH_KEX_DH_GEX_REQUEST:
        case SSH_USERAUTH_INFO_RESPONSE:
        case SSH_USERAUTH_REQUEST:
        case SSH_USERAUTH_FAILURE:
        case SSH_USERAUTH_SUCCESS:
        case SSH_USERAUTH_BANNER:
        case SSH_USERAUTH_METHOD_REPLY:
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
            fix_RFC4251_5_typed_payload_fields(pkt[i].type, &pkt[i].u.typed);
            break;
        default:
            pkt[i].type = SSH_OPAQUE;
            pkt[i].u.opaque.len = 0;
            break;
        }
    }
    ssh_fix_sequence_constraints(pkt, num_packets);
}
