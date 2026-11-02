#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "llm/dns/dns.h"
#include "llm/ssh/ssh.h"
#include "llm/tls/tls.h"
#include "llm/dicom/dicom.h"

static int failures = 0;

#define CHECK(cond, label) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        failures++; \
    } \
} while (0)

static void put16be(uint8_t *b, size_t *o, uint16_t v) { b[(*o)++] = (uint8_t)(v >> 8); b[(*o)++] = (uint8_t)v; }
static void put24be(uint8_t *b, size_t *o, uint32_t v) { b[(*o)++] = (uint8_t)(v >> 16); b[(*o)++] = (uint8_t)(v >> 8); b[(*o)++] = (uint8_t)v; }
static void put32be(uint8_t *b, size_t *o, uint32_t v) { b[(*o)++] = (uint8_t)(v >> 24); b[(*o)++] = (uint8_t)(v >> 16); b[(*o)++] = (uint8_t)(v >> 8); b[(*o)++] = (uint8_t)v; }
static void put16le(uint8_t *b, size_t *o, uint16_t v) { b[(*o)++] = (uint8_t)v; b[(*o)++] = (uint8_t)(v >> 8); }
static void put32le(uint8_t *b, size_t *o, uint32_t v) { b[(*o)++] = (uint8_t)v; b[(*o)++] = (uint8_t)(v >> 8); b[(*o)++] = (uint8_t)(v >> 16); b[(*o)++] = (uint8_t)(v >> 24); }
static void put_bytes(uint8_t *b, size_t *o, const void *src, size_t n) { memcpy(b + *o, src, n); *o += n; }


#define ROUNDTRIP_MAX 262144u
static uint8_t rt_out1[ROUNDTRIP_MAX];
static uint8_t rt_out2[ROUNDTRIP_MAX];
static dns_packet_t dns_rt1[32], dns_rt2[32];
static ssh_packet_t ssh_rt1[32], ssh_rt2[32];
static tls_packet_t tls_rt1[32], tls_rt2[32];
static dicom_packet_t dicom_rt1[16], dicom_rt2[16];

static void check_bytes_equal(const uint8_t *a, u32 alen, const uint8_t *b, u32 blen, const char *label) {
    if (alen != blen || memcmp(a, b, alen) != 0) {
        u32 diff = 0;
        u32 lim = alen < blen ? alen : blen;
        while (diff < lim && a[diff] == b[diff]) diff++;
        if (diff < lim) {
            fprintf(stderr, "FAIL: %s stable bytes differ len1=%u len2=%u first_diff=%u 0x%02x!=0x%02x\n", label, alen, blen, diff, a[diff], b[diff]);
        } else {
            fprintf(stderr, "FAIL: %s stable bytes differ len1=%u len2=%u first_diff=end\n", label, alen, blen);
        }
        failures++;
    }
}

static void check_dns_metamorphic(const uint8_t *input, size_t len, const char *label, int use_fixer) {
    memset(dns_rt1, 0, sizeof(dns_rt1));
    memset(dns_rt2, 0, sizeof(dns_rt2));
    size_t n = parse_dns_msg(input, (u32)len, dns_rt1, 32);
    char msg[256];
    snprintf(msg, sizeof(msg), "%s DNS parse", label);
    CHECK(n > 0, msg);
    if (n == 0) return;
    if (use_fixer) fix_dns(dns_rt1, (int)n);
    u32 out_len1 = sizeof(rt_out1);
    snprintf(msg, sizeof(msg), "%s DNS reassemble first", label);
    CHECK(reassemble_dns_msgs(dns_rt1, (u32)n, rt_out1, &out_len1) == 0, msg);
    if (out_len1 == sizeof(rt_out1)) return;
    size_t rn = parse_dns_msg(rt_out1, out_len1, dns_rt2, 32);
    snprintf(msg, sizeof(msg), "%s DNS parse second", label);
    CHECK(rn > 0, msg);
    if (rn == 0) return;
    if (use_fixer) fix_dns(dns_rt2, (int)rn);
    u32 out_len2 = sizeof(rt_out2);
    snprintf(msg, sizeof(msg), "%s DNS reassemble second", label);
    CHECK(reassemble_dns_msgs(dns_rt2, (u32)rn, rt_out2, &out_len2) == 0, msg);
    snprintf(msg, sizeof(msg), "%s DNS %smetamorphic", label, use_fixer ? "fixed " : "");
    check_bytes_equal(rt_out1, out_len1, rt_out2, out_len2, msg);
}

static void check_ssh_metamorphic(const uint8_t *input, size_t len, const char *label, int use_fixer) {
    memset(ssh_rt1, 0, sizeof(ssh_rt1));
    memset(ssh_rt2, 0, sizeof(ssh_rt2));
    size_t n = parse_ssh_msg(input, (u32)len, ssh_rt1, 32);
    char msg[256];
    snprintf(msg, sizeof(msg), "%s SSH parse", label);
    CHECK(n > 0, msg);
    if (n == 0) return;
    if (use_fixer) fix_ssh(ssh_rt1, (int)n);
    u32 out_len1 = sizeof(rt_out1);
    snprintf(msg, sizeof(msg), "%s SSH reassemble first", label);
    CHECK(reassemble_ssh_msgs(ssh_rt1, (u32)n, rt_out1, &out_len1) == 0, msg);
    size_t rn = parse_ssh_msg(rt_out1, out_len1, ssh_rt2, 32);
    snprintf(msg, sizeof(msg), "%s SSH parse second", label);
    CHECK(rn > 0, msg);
    if (rn == 0) return;
    if (use_fixer) fix_ssh(ssh_rt2, (int)rn);
    u32 out_len2 = sizeof(rt_out2);
    snprintf(msg, sizeof(msg), "%s SSH reassemble second", label);
    CHECK(reassemble_ssh_msgs(ssh_rt2, (u32)rn, rt_out2, &out_len2) == 0, msg);
    snprintf(msg, sizeof(msg), "%s SSH %smetamorphic", label, use_fixer ? "fixed " : "");
    check_bytes_equal(rt_out1, out_len1, rt_out2, out_len2, msg);
}

static void check_tls_metamorphic(const uint8_t *input, size_t len, const char *label, int use_fixer) {
    memset(tls_rt1, 0, sizeof(tls_rt1));
    memset(tls_rt2, 0, sizeof(tls_rt2));
    size_t n = parse_tls_msg(input, (u32)len, tls_rt1, 32);
    char msg[256];
    snprintf(msg, sizeof(msg), "%s TLS parse", label);
    CHECK(n > 0, msg);
    if (n == 0) return;
    if (use_fixer) fix_tls(tls_rt1, (int)n);
    u32 out_len1 = sizeof(rt_out1);
    snprintf(msg, sizeof(msg), "%s TLS reassemble first", label);
    CHECK(reassemble_tls_msgs(tls_rt1, (u32)n, rt_out1, &out_len1) == 0, msg);
    size_t rn = parse_tls_msg(rt_out1, out_len1, tls_rt2, 32);
    snprintf(msg, sizeof(msg), "%s TLS parse second", label);
    CHECK(rn > 0, msg);
    if (rn == 0) return;
    if (use_fixer) fix_tls(tls_rt2, (int)rn);
    u32 out_len2 = sizeof(rt_out2);
    snprintf(msg, sizeof(msg), "%s TLS reassemble second", label);
    CHECK(reassemble_tls_msgs(tls_rt2, (u32)rn, rt_out2, &out_len2) == 0, msg);
    snprintf(msg, sizeof(msg), "%s TLS %smetamorphic", label, use_fixer ? "fixed " : "");
    check_bytes_equal(rt_out1, out_len1, rt_out2, out_len2, msg);
}

static void check_dicom_metamorphic(const uint8_t *input, size_t len, const char *label, int use_fixer) {
    memset(dicom_rt1, 0, sizeof(dicom_rt1));
    memset(dicom_rt2, 0, sizeof(dicom_rt2));
    size_t n = parse_dicom_msg(input, (u32)len, dicom_rt1, 16);
    char msg[256];
    snprintf(msg, sizeof(msg), "%s DICOM parse", label);
    CHECK(n > 0, msg);
    if (n == 0) return;
    if (use_fixer) fix_dicom(dicom_rt1, (int)n);
    u32 out_len1 = sizeof(rt_out1);
    snprintf(msg, sizeof(msg), "%s DICOM reassemble first", label);
    CHECK(reassemble_dicom_msgs(dicom_rt1, (u32)n, rt_out1, &out_len1) == 0, msg);
    size_t rn = parse_dicom_msg(rt_out1, out_len1, dicom_rt2, 16);
    snprintf(msg, sizeof(msg), "%s DICOM parse second", label);
    CHECK(rn > 0, msg);
    if (rn == 0) return;
    if (use_fixer) fix_dicom(dicom_rt2, (int)rn);
    u32 out_len2 = sizeof(rt_out2);
    snprintf(msg, sizeof(msg), "%s DICOM reassemble second", label);
    CHECK(reassemble_dicom_msgs(dicom_rt2, (u32)rn, rt_out2, &out_len2) == 0, msg);
    snprintf(msg, sizeof(msg), "%s DICOM %smetamorphic", label, use_fixer ? "fixed " : "");
    check_bytes_equal(rt_out1, out_len1, rt_out2, out_len2, msg);
}

static void put_dns_name(uint8_t *b, size_t *o, const char *a, const char *c) {
    size_t la = strlen(a), lc = strlen(c);
    b[(*o)++] = (uint8_t)la; put_bytes(b, o, a, la);
    b[(*o)++] = (uint8_t)lc; put_bytes(b, o, c, lc);
    b[(*o)++] = 0;
}

static size_t make_dns_msg(uint8_t *b, uint8_t opcode, int edns) {
    size_t o = 0;
    put16be(b, &o, 0x1234);
    put16be(b, &o, (uint16_t)((opcode & 0xf) << 11) | 0x0100);
    put16be(b, &o, 1);
    put16be(b, &o, 0);
    put16be(b, &o, opcode == 5 ? 1 : 0);
    put16be(b, &o, edns ? 1 : 0);
    put_dns_name(b, &o, "example", "com");
    put16be(b, &o, opcode == 5 ? 6 : 1);
    put16be(b, &o, 1);
    if (opcode == 5) {
        put_dns_name(b, &o, "www", "example");
        put16be(b, &o, 1);
        put16be(b, &o, 1);
        put32be(b, &o, 0);
        put16be(b, &o, 4);
        b[o++] = 127; b[o++] = 0; b[o++] = 0; b[o++] = 1;
    }
    if (edns) {
        b[o++] = 0;
        put16be(b, &o, 41);
        put16be(b, &o, 1232);
        put32be(b, &o, 0);
        put16be(b, &o, 0);
    }
    return o;
}


static void put_dns_rr_a(uint8_t *b, size_t *o, uint16_t name_ptr, uint32_t addr) {
    put16be(b, o, name_ptr);
    put16be(b, o, 1);
    put16be(b, o, 1);
    put32be(b, o, 60);
    put16be(b, o, 4);
    b[(*o)++] = (uint8_t)(addr >> 24);
    b[(*o)++] = (uint8_t)(addr >> 16);
    b[(*o)++] = (uint8_t)(addr >> 8);
    b[(*o)++] = (uint8_t)addr;
}

static size_t make_dns_response_complex(uint8_t *b) {
    size_t o = 0;
    put16be(b, &o, 0xbeef);
    put16be(b, &o, 0x8180); /* standard response, no error */
    put16be(b, &o, 1);
    put16be(b, &o, 2);
    put16be(b, &o, 1);
    put16be(b, &o, 2);
    put_dns_name(b, &o, "example", "com");
    put16be(b, &o, 1);
    put16be(b, &o, 1);
    put_dns_rr_a(b, &o, 0xc00c, 0x7f000001u);
    put16be(b, &o, 0xc00c); /* CNAME */
    put16be(b, &o, 5);
    put16be(b, &o, 1);
    put32be(b, &o, 60);
    size_t rdpos = o; put16be(b, &o, 0);
    size_t rstart = o; put_dns_name(b, &o, "alias", "example");
    b[rdpos] = (uint8_t)((o - rstart) >> 8); b[rdpos + 1] = (uint8_t)(o - rstart);
    put16be(b, &o, 0xc00c); /* NS authority */
    put16be(b, &o, 2);
    put16be(b, &o, 1);
    put32be(b, &o, 60);
    rdpos = o; put16be(b, &o, 0);
    rstart = o; put_dns_name(b, &o, "ns1", "example");
    b[rdpos] = (uint8_t)((o - rstart) >> 8); b[rdpos + 1] = (uint8_t)(o - rstart);
    put_dns_name(b, &o, "ns1", "example");
    put16be(b, &o, 1);
    put16be(b, &o, 1);
    put32be(b, &o, 60);
    put16be(b, &o, 4);
    b[o++] = 127; b[o++] = 0; b[o++] = 0; b[o++] = 53;
    b[o++] = 0; /* EDNS OPT */
    put16be(b, &o, 41);
    put16be(b, &o, 1232);
    put32be(b, &o, 0x00008000u); /* DO bit */
    put16be(b, &o, 8);
    put16be(b, &o, 12); put16be(b, &o, 0); /* padding option */
    put16be(b, &o, 10); put16be(b, &o, 0); /* cookie-like empty option */
    return o;
}

static size_t make_dns_update_complex(uint8_t *b) {
    size_t o = 0;
    put16be(b, &o, 0x7654);
    put16be(b, &o, (uint16_t)(5u << 11));
    put16be(b, &o, 1); /* zone */
    put16be(b, &o, 1); /* prerequisite */
    put16be(b, &o, 1); /* update */
    put16be(b, &o, 1); /* additional OPT */
    put_dns_name(b, &o, "example", "com");
    put16be(b, &o, 6); put16be(b, &o, 1);
    put_dns_name(b, &o, "old", "example");
    put16be(b, &o, 1); put16be(b, &o, 255); put32be(b, &o, 0); put16be(b, &o, 0);
    put_dns_name(b, &o, "new", "example");
    put16be(b, &o, 1); put16be(b, &o, 1); put32be(b, &o, 30); put16be(b, &o, 4);
    b[o++] = 10; b[o++] = 0; b[o++] = 0; b[o++] = 1;
    b[o++] = 0; put16be(b, &o, 41); put16be(b, &o, 4096); put32be(b, &o, 0); put16be(b, &o, 0);
    return o;
}

static size_t make_dns_concatenated(uint8_t *b) {
    size_t o = make_dns_msg(b, 0, 1);
    o += make_dns_msg(b + o, 4, 0);
    return o;
}

static void sanity_dns(void) {
    uint8_t buf[2048], out[4096];
    const uint8_t opcodes[] = {0, 1, 2, 4, 5};
    for (size_t i = 0; i < sizeof(opcodes); i++) {
        size_t len = make_dns_msg(buf, opcodes[i], opcodes[i] == 0);
        check_dns_metamorphic(buf, len, "DNS RFC opcode seed", 0);
        check_dns_metamorphic(buf, len, "DNS RFC opcode seed", 1);
        static dns_packet_t pkts[4], reparsed[4];
        memset(pkts, 0, sizeof(pkts));
        memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_dns_msg(buf, (u32)len, pkts, 4);
        CHECK(n == 1, "DNS parse RFC opcode");
        if (n != 1) continue;
        CHECK(pkts[0].u.dns_message.header.opcode == opcodes[i], "DNS opcode preserved by parser");
        fix_dns(pkts, (int)n);
        u32 out_len = sizeof(out);
        CHECK(reassemble_dns_msgs(pkts, (u32)n, out, &out_len) == 0, "DNS reassemble after fix");
        size_t rn = parse_dns_msg(out, out_len, reparsed, 4);
        CHECK(rn == 1, "DNS parse after reassemble");
        if (rn == 1) CHECK(reparsed[0].u.dns_message.header.z == 0, "DNS fixer clears Z bits");
    }
    {
        size_t len = make_dns_response_complex(buf);
        check_dns_metamorphic(buf, len, "DNS compressed response EDNS", 0);
        check_dns_metamorphic(buf, len, "DNS compressed response EDNS", 1);
    }
    {
        size_t len = make_dns_update_complex(buf);
        check_dns_metamorphic(buf, len, "DNS RFC2136 update", 0);
        check_dns_metamorphic(buf, len, "DNS RFC2136 update", 1);
    }
    {
        size_t len = make_dns_concatenated(buf);
        check_dns_metamorphic(buf, len, "DNS concatenated messages", 0);
        check_dns_metamorphic(buf, len, "DNS concatenated messages", 1);
    }
}

static void ssh_put_string(uint8_t *b, size_t *o, const void *s, size_t n) { put32be(b, o, (uint32_t)n); put_bytes(b, o, s, n); }
static void ssh_put_cstring(uint8_t *b, size_t *o, const char *s) { ssh_put_string(b, o, s, strlen(s)); }

static size_t wrap_ssh_packet(uint8_t *out, const uint8_t *payload, size_t payload_len) {
    size_t o = 0;
    uint32_t pad = 4;
    while (((4 + 1 + payload_len + pad) % 8) != 0) pad++;
    put32be(out, &o, (uint32_t)(1 + payload_len + pad));
    out[o++] = (uint8_t)pad;
    put_bytes(out, &o, payload, payload_len);
    for (uint32_t i = 0; i < pad; i++) out[o++] = (uint8_t)(0xa0 + i);
    return o;
}

static ssh_packet_type_t ssh_expected_type(uint8_t code) {
    switch (code) {
        case SSH_MSG_KEXINIT: return SSH_KEXINIT;
        case SSH_MSG_KEXDH_INIT: return SSH_KEXDH_INIT;
        case SSH_MSG_SERVICE_REQUEST: return SSH_SERVICE_REQUEST;
        case SSH_MSG_NEWKEYS: return SSH_NEWKEYS;
        case SSH_MSG_DISCONNECT: return SSH_DISCONNECT;
        case SSH_MSG_IGNORE: return SSH_IGNORE;
        case SSH_MSG_UNIMPLEMENTED: return SSH_UNIMPLEMENTED;
        case SSH_MSG_DEBUG: return SSH_DEBUG;
        case SSH_MSG_SERVICE_ACCEPT: return SSH_SERVICE_ACCEPT;
        case SSH_MSG_KEXDH_REPLY: return SSH_KEXDH_REPLY;
        case SSH_MSG_USERAUTH_REQUEST: return SSH_USERAUTH_REQUEST;
        case SSH_MSG_USERAUTH_FAILURE: return SSH_USERAUTH_FAILURE;
        case SSH_MSG_USERAUTH_SUCCESS: return SSH_USERAUTH_SUCCESS;
        case SSH_MSG_USERAUTH_BANNER: return SSH_USERAUTH_BANNER;
        case SSH_MSG_USERAUTH_METHOD_REPLY: return SSH_USERAUTH_METHOD_REPLY;
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

static size_t make_ssh_payload(uint8_t *p, uint8_t code) {
    size_t o = 0;
    p[o++] = code;
    switch (code) {
        case SSH_MSG_KEXINIT:
            memset(p + o, 0x42, 16); o += 16;
            ssh_put_cstring(p, &o, "diffie-hellman-group14-sha1");
            ssh_put_cstring(p, &o, "ssh-rsa");
            ssh_put_cstring(p, &o, "aes128-ctr");
            ssh_put_cstring(p, &o, "aes128-ctr");
            ssh_put_cstring(p, &o, "hmac-sha1");
            ssh_put_cstring(p, &o, "hmac-sha1");
            ssh_put_cstring(p, &o, "none");
            ssh_put_cstring(p, &o, "none");
            ssh_put_cstring(p, &o, "");
            ssh_put_cstring(p, &o, "");
            p[o++] = 0;
            put32be(p, &o, 0);
            break;
        case SSH_MSG_KEXDH_INIT: { uint8_t e[] = {1}; ssh_put_string(p, &o, e, sizeof(e)); break; }
        case SSH_MSG_SERVICE_REQUEST: ssh_put_cstring(p, &o, "ssh-userauth"); break;
        case SSH_MSG_NEWKEYS: break;
        case SSH_MSG_DISCONNECT: put32be(p, &o, 11); ssh_put_cstring(p, &o, "disconnect"); ssh_put_cstring(p, &o, "en"); break;
        case SSH_MSG_IGNORE: ssh_put_cstring(p, &o, "ignore"); break;
        case SSH_MSG_UNIMPLEMENTED: put32be(p, &o, 7); break;
        case SSH_MSG_DEBUG: p[o++] = 0; ssh_put_cstring(p, &o, "debug"); ssh_put_cstring(p, &o, "en"); break;
        case SSH_MSG_SERVICE_ACCEPT: ssh_put_cstring(p, &o, "ssh-userauth"); break;
        case SSH_MSG_KEXDH_REPLY: { uint8_t f[] = {1}; ssh_put_cstring(p, &o, "ssh-rsa"); ssh_put_string(p, &o, f, sizeof(f)); ssh_put_cstring(p, &o, "sig"); break; }
        case SSH_MSG_USERAUTH_REQUEST: ssh_put_cstring(p, &o, "user"); ssh_put_cstring(p, &o, "ssh-connection"); ssh_put_cstring(p, &o, "none"); break;
        case SSH_MSG_USERAUTH_FAILURE: ssh_put_cstring(p, &o, "publickey,password,none"); p[o++] = 0; break;
        case SSH_MSG_USERAUTH_SUCCESS: break;
        case SSH_MSG_USERAUTH_BANNER: ssh_put_cstring(p, &o, "banner"); ssh_put_cstring(p, &o, "en"); break;
        case SSH_MSG_USERAUTH_METHOD_REPLY: ssh_put_cstring(p, &o, "ssh-rsa"); ssh_put_cstring(p, &o, "blob"); break;
        case SSH_MSG_GLOBAL_REQUEST: ssh_put_cstring(p, &o, "tcpip-forward"); p[o++] = 0; break;
        case SSH_MSG_REQUEST_SUCCESS: case SSH_MSG_REQUEST_FAILURE: break;
        case SSH_MSG_CHANNEL_OPEN: ssh_put_cstring(p, &o, "session"); put32be(p, &o, 0); put32be(p, &o, 65536); put32be(p, &o, 32768); break;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: put32be(p, &o, 0); put32be(p, &o, 0); put32be(p, &o, 65536); put32be(p, &o, 32768); break;
        case SSH_MSG_CHANNEL_OPEN_FAILURE: put32be(p, &o, 0); put32be(p, &o, 2); ssh_put_cstring(p, &o, "failed"); ssh_put_cstring(p, &o, "en"); break;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST: put32be(p, &o, 0); put32be(p, &o, 32768); break;
        case SSH_MSG_CHANNEL_DATA: put32be(p, &o, 0); ssh_put_cstring(p, &o, "data"); break;
        case SSH_MSG_CHANNEL_EXTENDED_DATA: put32be(p, &o, 0); put32be(p, &o, 1); ssh_put_cstring(p, &o, "stderr"); break;
        case SSH_MSG_CHANNEL_EOF: case SSH_MSG_CHANNEL_CLOSE: case SSH_MSG_CHANNEL_SUCCESS: case SSH_MSG_CHANNEL_FAILURE: put32be(p, &o, 0); break;
        case SSH_MSG_CHANNEL_REQUEST: put32be(p, &o, 0); ssh_put_cstring(p, &o, "exec"); p[o++] = 0; break;
        default: break;
    }
    return o;
}

static size_t make_ssh_userauth_request_payload(uint8_t *p, const char *method) {
    size_t o = 0;
    p[o++] = SSH_MSG_USERAUTH_REQUEST;
    ssh_put_cstring(p, &o, "user");
    ssh_put_cstring(p, &o, "ssh-connection");
    ssh_put_cstring(p, &o, method);
    if (strcmp(method, "publickey") == 0) {
        const uint8_t key_blob[] = {0x00, 0x00, 0x00, 0x07, 's', 's', 'h', '-', 'r', 's', 'a', 0x01, 0x00, 0x01};
        p[o++] = 1;
        ssh_put_cstring(p, &o, "ssh-rsa");
        ssh_put_string(p, &o, key_blob, sizeof(key_blob));
        ssh_put_cstring(p, &o, "signature");
    } else if (strcmp(method, "password") == 0) {
        p[o++] = 1;
        ssh_put_cstring(p, &o, "old-password");
        ssh_put_cstring(p, &o, "new-password");
    } else if (strcmp(method, "hostbased") == 0) {
        const uint8_t host_key_blob[] = {0x00, 0x00, 0x00, 0x07, 's', 's', 'h', '-', 'r', 's', 'a', 0x01, 0x00, 0x01};
        ssh_put_cstring(p, &o, "ssh-rsa");
        ssh_put_string(p, &o, host_key_blob, sizeof(host_key_blob));
        ssh_put_cstring(p, &o, "client.example");
        ssh_put_cstring(p, &o, "client-user");
        ssh_put_cstring(p, &o, "hostbased-signature");
    }
    return o;
}


static size_t make_ssh_stream_with_banner(uint8_t *b) {
    size_t o = 0;
    const char *banner = "SSH-2.0-OpenSSH_9.6 LemurMetamorphic\r\n";
    put_bytes(b, &o, banner, strlen(banner));
    uint8_t payload[4096];
    size_t plen = make_ssh_payload(payload, SSH_MSG_KEXINIT);
    o += wrap_ssh_packet(b + o, payload, plen);
    plen = make_ssh_payload(payload, SSH_MSG_SERVICE_REQUEST);
    o += wrap_ssh_packet(b + o, payload, plen);
    plen = make_ssh_payload(payload, SSH_MSG_USERAUTH_REQUEST);
    o += wrap_ssh_packet(b + o, payload, plen);
    plen = make_ssh_payload(payload, SSH_MSG_CHANNEL_OPEN);
    o += wrap_ssh_packet(b + o, payload, plen);
    return o;
}

static size_t make_ssh_transport_sequence(uint8_t *b) {
    size_t o = 0;
    uint8_t payload[4096];
    const uint8_t seq[] = {SSH_MSG_IGNORE, SSH_MSG_DEBUG, SSH_MSG_GLOBAL_REQUEST, SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_DATA};
    for (size_t i = 0; i < sizeof(seq); i++) {
        size_t plen = make_ssh_payload(payload, seq[i]);
        o += wrap_ssh_packet(b + o, payload, plen);
    }
    return o;
}

static void sanity_ssh(void) {
    const uint8_t codes[] = {1,2,3,4,5,6,20,21,30,31,50,51,52,53,60,80,81,82,90,91,92,93,94,95,96,97,98,99,100};
    uint8_t payload[8192], wire[9000], out[9000];
    for (size_t i = 0; i < sizeof(codes); i++) {
        size_t plen = make_ssh_payload(payload, codes[i]);
        size_t wlen = wrap_ssh_packet(wire, payload, plen);
        check_ssh_metamorphic(wire, wlen, "SSH RFC message seed", 0);
        check_ssh_metamorphic(wire, wlen, "SSH RFC message seed", 1);
        static ssh_packet_t pkts[4], reparsed[4];
        memset(pkts, 0, sizeof(pkts));
        memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_ssh_msg(wire, (u32)wlen, pkts, 4);
        CHECK(n == 1, "SSH parse RFC message");
        if (n != 1) continue;
        CHECK(pkts[0].type == ssh_expected_type(codes[i]), "SSH message type classification");
        fix_ssh(pkts, (int)n);
        u32 out_len = sizeof(out);
        CHECK(reassemble_ssh_msgs(pkts, (u32)n, out, &out_len) == 0, "SSH reassemble after fix");
        size_t rn = parse_ssh_msg(out, out_len, reparsed, 4);
        CHECK(rn == 1, "SSH parse after reassemble");
        if (rn == 1) CHECK(reparsed[0].type == ssh_expected_type(codes[i]), "SSH type preserved after reassemble");
    }
    {
        size_t wlen = make_ssh_stream_with_banner(wire);
        check_ssh_metamorphic(wire, wlen, "SSH banner plus packets", 0);
        check_ssh_metamorphic(wire, wlen, "SSH banner plus packets", 1);
    }
    {
        size_t wlen = make_ssh_transport_sequence(wire);
        check_ssh_metamorphic(wire, wlen, "SSH transport sequence", 0);
        check_ssh_metamorphic(wire, wlen, "SSH transport sequence", 1);
    }
    {
        const char *methods[] = {"publickey", "password", "hostbased"};
        for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
            size_t plen = make_ssh_userauth_request_payload(payload, methods[i]);
            size_t wlen = wrap_ssh_packet(wire, payload, plen);
            check_ssh_metamorphic(wire, wlen, "SSH RFC4252 USERAUTH_REQUEST method", 0);
            check_ssh_metamorphic(wire, wlen, "SSH RFC4252 USERAUTH_REQUEST method", 1);
            static ssh_packet_t pkts[2], reparsed[2];
            memset(pkts, 0, sizeof(pkts));
            memset(reparsed, 0, sizeof(reparsed));
            memset(pkts, 0, sizeof(pkts));
            memset(reparsed, 0, sizeof(reparsed));
            size_t n = parse_ssh_msg(wire, (u32)wlen, pkts, 2);
            CHECK(n == 1, "SSH parse USERAUTH_REQUEST method");
            if (n == 1) {
                CHECK(pkts[0].type == SSH_USERAUTH_REQUEST, "SSH USERAUTH_REQUEST classified");
                CHECK(pkts[0].u.typed.string_count >= 5, "SSH USERAUTH_REQUEST method fields parsed");
                fix_ssh(pkts, (int)n);
                u32 out_len = sizeof(out);
                CHECK(reassemble_ssh_msgs(pkts, (u32)n, out, &out_len) == 0, "SSH USERAUTH_REQUEST method reassembled");
                CHECK(parse_ssh_msg(out, out_len, reparsed, 2) == 1, "SSH USERAUTH_REQUEST method reparsed");
            }
        }
    }
}

static size_t make_tls_record(uint8_t *b, uint8_t type, uint8_t hs_type) {
    size_t o = 0;
    b[o++] = type; b[o++] = 3; b[o++] = 3;
    size_t len_pos = o; put16be(b, &o, 0);
    size_t frag_start = o;
    if (type == TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC) {
        b[o++] = 1;
    } else if (type == TLS_CONTENTTYPE_ALERT) {
        b[o++] = 2; b[o++] = TLS_ALERT_HANDSHAKE_FAILURE;
    } else if (type == TLS_CONTENTTYPE_APPLICATION_DATA) {
        b[o++] = 'x'; b[o++] = 'y';
    } else if (type == TLS_CONTENTTYPE_HANDSHAKE) {
        b[o++] = hs_type;
        size_t hlen_pos = o; put24be(b, &o, 0);
        size_t body_start = o;
        if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
            b[o++] = 3; b[o++] = 3;
            memset(b + o, 0x55, 32); o += 32;
            b[o++] = 0;
            put16be(b, &o, 2); put16be(b, &o, 0x002f);
            b[o++] = 1; b[o++] = 0;
            put16be(b, &o, 0);
        }
        uint32_t blen = (uint32_t)(o - body_start);
        b[hlen_pos] = (uint8_t)(blen >> 16); b[hlen_pos + 1] = (uint8_t)(blen >> 8); b[hlen_pos + 2] = (uint8_t)blen;
    }
    uint16_t flen = (uint16_t)(o - frag_start);
    b[len_pos] = (uint8_t)(flen >> 8); b[len_pos + 1] = (uint8_t)flen;
    return o;
}


static void tls_put_extension(uint8_t *ext, size_t *eo, uint16_t type, const uint8_t *data, size_t data_len) {
    put16be(ext, eo, type);
    put16be(ext, eo, (uint16_t)data_len);
    put_bytes(ext, eo, data, data_len);
}

static size_t make_tls_client_hello_ext(uint8_t *b) {
    uint8_t ext[1024]; size_t eo = 0;
    uint8_t tmp[512]; size_t to = 0;

    const char *host = "example.com";
    to = 0;
    put16be(tmp, &to, (uint16_t)(1 + 2 + strlen(host)));
    tmp[to++] = 0;
    put16be(tmp, &to, (uint16_t)strlen(host));
    put_bytes(tmp, &to, host, strlen(host));
    tls_put_extension(ext, &eo, 0, tmp, to);

    to = 0;
    put16be(tmp, &to, 6);
    put16be(tmp, &to, 0x001d);
    put16be(tmp, &to, 0x0017);
    put16be(tmp, &to, 0x0018);
    tls_put_extension(ext, &eo, 10, tmp, to);

    to = 0;
    put16be(tmp, &to, 6);
    put16be(tmp, &to, 0x0403);
    put16be(tmp, &to, 0x0503);
    put16be(tmp, &to, 0x0603);
    tls_put_extension(ext, &eo, 13, tmp, to);

    const char *alpn1 = "h2";
    const char *alpn2 = "http/1.1";
    to = 0;
    put16be(tmp, &to, (uint16_t)(1 + strlen(alpn1) + 1 + strlen(alpn2)));
    tmp[to++] = (uint8_t)strlen(alpn1); put_bytes(tmp, &to, alpn1, strlen(alpn1));
    tmp[to++] = (uint8_t)strlen(alpn2); put_bytes(tmp, &to, alpn2, strlen(alpn2));
    tls_put_extension(ext, &eo, 16, tmp, to);

    to = 0;
    put16be(tmp, &to, 2);
    tmp[to++] = 0; tmp[to++] = 1; /* status_request v2-ish opaque data */
    tls_put_extension(ext, &eo, 5, tmp, to);

    size_t o = 0;
    b[o++] = TLS_CONTENTTYPE_HANDSHAKE; b[o++] = 3; b[o++] = 3;
    size_t rec_len_pos = o; put16be(b, &o, 0);
    size_t frag_start = o;
    b[o++] = TLS_HANDSHAKE_CLIENT_HELLO;
    size_t hs_len_pos = o; put24be(b, &o, 0);
    size_t body_start = o;
    b[o++] = 3; b[o++] = 3;
    for (int i = 0; i < 32; i++) b[o++] = (uint8_t)(0x30 + i);
    b[o++] = 4; b[o++] = 1; b[o++] = 2; b[o++] = 3; b[o++] = 4;
    put16be(b, &o, 8);
    put16be(b, &o, 0x002f); put16be(b, &o, 0x0035); put16be(b, &o, 0xc02f); put16be(b, &o, 0x009c);
    b[o++] = 1; b[o++] = 0;
    put16be(b, &o, (uint16_t)eo);
    put_bytes(b, &o, ext, eo);
    uint32_t body_len = (uint32_t)(o - body_start);
    b[hs_len_pos] = (uint8_t)(body_len >> 16);
    b[hs_len_pos + 1] = (uint8_t)(body_len >> 8);
    b[hs_len_pos + 2] = (uint8_t)body_len;
    uint16_t rec_len = (uint16_t)(o - frag_start);
    b[rec_len_pos] = (uint8_t)(rec_len >> 8);
    b[rec_len_pos + 1] = (uint8_t)rec_len;
    return o;
}

static size_t make_tls_record_sequence(uint8_t *b) {
    size_t o = make_tls_client_hello_ext(b);
    o += make_tls_record(b + o, TLS_CONTENTTYPE_APPLICATION_DATA, 0);
    o += make_tls_record(b + o, TLS_CONTENTTYPE_ALERT, 0);
    return o;
}


static size_t make_tls13_certificate_with_extensions(uint8_t *b) {
    size_t o = 0;
    b[o++] = TLS_CONTENTTYPE_HANDSHAKE;
    b[o++] = 3; b[o++] = 3;
    size_t rec_len_pos = o; put16be(b, &o, 0);
    size_t frag_start = o;
    b[o++] = TLS_HANDSHAKE_CERTIFICATE;
    size_t hs_len_pos = o; put24be(b, &o, 0);
    size_t body_start = o;
    b[o++] = 0; /* certificate_request_context length */
    size_t list_len_pos = o; put24be(b, &o, 0);
    size_t list_start = o;
    uint8_t cert[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x05, 0x00};
    put24be(b, &o, sizeof(cert));
    put_bytes(b, &o, cert, sizeof(cert));
    uint8_t cert_ext[16]; size_t eo = 0;
    uint8_t status_payload[] = {0x01, 0x02, 0x03};
    tls_put_extension(cert_ext, &eo, 5, status_payload, sizeof(status_payload));
    put16be(b, &o, (uint16_t)eo);
    put_bytes(b, &o, cert_ext, eo);
    uint32_t list_len = (uint32_t)(o - list_start);
    b[list_len_pos] = (uint8_t)(list_len >> 16);
    b[list_len_pos + 1] = (uint8_t)(list_len >> 8);
    b[list_len_pos + 2] = (uint8_t)list_len;
    uint32_t body_len = (uint32_t)(o - body_start);
    b[hs_len_pos] = (uint8_t)(body_len >> 16);
    b[hs_len_pos + 1] = (uint8_t)(body_len >> 8);
    b[hs_len_pos + 2] = (uint8_t)body_len;
    uint16_t rec_len = (uint16_t)(o - frag_start);
    b[rec_len_pos] = (uint8_t)(rec_len >> 8);
    b[rec_len_pos + 1] = (uint8_t)rec_len;
    return o;
}

static void sanity_tls(void) {
    uint8_t buf[8192], out[8192];
    const uint8_t records[] = {20,21,23};
    for (size_t i = 0; i < sizeof(records); i++) {
        size_t len = make_tls_record(buf, records[i], 0);
        check_tls_metamorphic(buf, len, "TLS record seed", 0);
        check_tls_metamorphic(buf, len, "TLS record seed", 1);
        static tls_packet_t pkts[2], reparsed[2];
        memset(pkts, 0, sizeof(pkts));
        memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_tls_msg(buf, (u32)len, pkts, 2);
        CHECK(n == 1, "TLS parse record");
        if (n != 1) continue;
        fix_tls(pkts, (int)n);
        u32 out_len = sizeof(out);
        CHECK(reassemble_tls_msgs(pkts, (u32)n, out, &out_len) == 0, "TLS reassemble record");
        CHECK(parse_tls_msg(out, out_len, reparsed, 2) == 1, "TLS parse record after reassemble");
    }
    const uint8_t hs[] = {0,1,2,11,12,13,14,15,16,20};
    for (size_t i = 0; i < sizeof(hs); i++) {
        size_t len = make_tls_record(buf, TLS_CONTENTTYPE_HANDSHAKE, hs[i]);
        check_tls_metamorphic(buf, len, "TLS handshake seed", 0);
        check_tls_metamorphic(buf, len, "TLS handshake seed", 1);
        static tls_packet_t pkts[2], reparsed[2];
        memset(pkts, 0, sizeof(pkts));
        memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_tls_msg(buf, (u32)len, pkts, 2);
        CHECK(n == 1, "TLS parse handshake");
        if (n != 1) continue;
        CHECK(pkts[0].u.handshake.handshake.msg_type == hs[i], "TLS handshake type parsed");
        fix_tls(pkts, (int)n);
        u32 out_len = sizeof(out);
        CHECK(reassemble_tls_msgs(pkts, (u32)n, out, &out_len) == 0, "TLS reassemble handshake");
        size_t rn = parse_tls_msg(out, out_len, reparsed, 2);
        CHECK(rn == 1, "TLS parse handshake after reassemble");
        if (rn == 1) CHECK(reparsed[0].u.handshake.handshake.msg_type == hs[i], "TLS handshake type preserved");
    }
    {
        size_t len = make_tls_client_hello_ext(buf);
        check_tls_metamorphic(buf, len, "TLS extended ClientHello", 0);
        check_tls_metamorphic(buf, len, "TLS extended ClientHello", 1);
    }
    {
        size_t len = make_tls_record_sequence(buf);
        check_tls_metamorphic(buf, len, "TLS record sequence", 0);
        check_tls_metamorphic(buf, len, "TLS record sequence", 1);
    }
    {
        size_t len = make_tls13_certificate_with_extensions(buf);
        check_tls_metamorphic(buf, len, "TLS1.3 certificate entry extensions", 0);
        check_tls_metamorphic(buf, len, "TLS1.3 certificate entry extensions", 1);
    }
}

static void dicom_put_elem_u16(uint8_t *b, size_t *o, uint16_t elem, uint16_t v) {
    put16le(b, o, 0x0000); put16le(b, o, elem); put32le(b, o, 2); put16le(b, o, v);
}
static void dicom_put_elem_text(uint8_t *b, size_t *o, uint16_t elem, const char *s) {
    put16le(b, o, 0x0000); put16le(b, o, elem); put32le(b, o, (uint32_t)strlen(s)); put_bytes(b, o, s, strlen(s));
}

static size_t make_dicom_dimse_pdata(uint8_t *b, uint16_t cmd) {
    uint8_t cmdset[1024]; size_t co = 0;
    put16le(cmdset, &co, 0); put16le(cmdset, &co, 0); put32le(cmdset, &co, 4);
    put32le(cmdset, &co, 0);
    dicom_put_elem_text(cmdset, &co, 0x0002, "1.2.840.10008.1.1");
    dicom_put_elem_text(cmdset, &co, 0x0003, "1.2.840.10008.1.1");
    dicom_put_elem_u16(cmdset, &co, 0x0100, cmd);
    dicom_put_elem_u16(cmdset, &co, 0x0110, 1);
    dicom_put_elem_text(cmdset, &co, 0x0600, "STORESCP");
    dicom_put_elem_u16(cmdset, &co, 0x0700, 0);
    dicom_put_elem_u16(cmdset, &co, 0x0800, (cmd == DICOM_DIMSE_C_ECHO_RQ || cmd == DICOM_DIMSE_C_CANCEL_RQ || cmd == DICOM_DIMSE_N_GET_RQ || cmd == DICOM_DIMSE_N_DELETE_RQ) ? 0x0101 : 0x0000);
    dicom_put_elem_text(cmdset, &co, 0x1000, "1.2.3.4.5");
    dicom_put_elem_text(cmdset, &co, 0x1001, "1.2.3.4.6");
    dicom_put_elem_u16(cmdset, &co, 0x1002, 1);
    dicom_put_elem_u16(cmdset, &co, 0x1008, 1);
    dicom_put_elem_text(cmdset, &co, 0x1030, "MOVESCU");
    dicom_put_elem_u16(cmdset, &co, 0x1031, 1);

    uint32_t group_len = (uint32_t)co - 12;
    cmdset[8]=(uint8_t)group_len; cmdset[9]=(uint8_t)(group_len>>8);
    cmdset[10]=(uint8_t)(group_len>>16); cmdset[11]=(uint8_t)(group_len>>24);
    size_t o = 0;
    b[o++] = DICOM_PDU_P_DATA_TF; b[o++] = 0;
    put32be(b, &o, (uint32_t)(4 + 2 + co));
    put32be(b, &o, (uint32_t)(2 + co));
    b[o++] = 1;
    b[o++] = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
    put_bytes(b, &o, cmdset, co);
    return o;
}

static size_t make_dicom_simple_pdu(uint8_t *b, uint8_t type) {
    size_t o = 0;
    if (type == DICOM_PDU_A_ASSOCIATE_RQ) {
        b[o++] = type; b[o++] = 0; size_t len_pos = o; put32be(b, &o, 0);
        put16be(b, &o, 1); put16be(b, &o, 0);
        memset(b + o, ' ', 16); memcpy(b + o, "ANY-SCP", 7); o += 16;
        memset(b + o, ' ', 16); memcpy(b + o, "LEMURSCU", 8); o += 16;
        memset(b + o, 0, 32); o += 32;
        b[o++] = 0x10; b[o++] = 0; put16be(b, &o, 21); put_bytes(b, &o, "1.2.840.10008.3.1.1.1", 21);
        uint32_t plen = (uint32_t)(o - 6); b[len_pos] = (uint8_t)(plen >> 24); b[len_pos+1] = (uint8_t)(plen >> 16); b[len_pos+2] = (uint8_t)(plen >> 8); b[len_pos+3] = (uint8_t)plen;
    } else if (type == DICOM_PDU_A_ASSOCIATE_AC) {
        b[o++] = type; b[o++] = 0; put32be(b, &o, 68); put16be(b, &o, 1); put16be(b, &o, 0); memset(b + o, ' ', 32); o += 32; memset(b + o, 0, 32); o += 32;
    } else if (type == DICOM_PDU_A_ASSOCIATE_RJ) {
        b[o++] = type; b[o++] = 0; put32be(b, &o, 4); b[o++] = 0; b[o++] = 1; b[o++] = 1; b[o++] = 1;
    } else if (type == DICOM_PDU_A_RELEASE_RQ || type == DICOM_PDU_A_RELEASE_RP) {
        b[o++] = type; b[o++] = 0; put32be(b, &o, 4); put32be(b, &o, 0);
    } else if (type == DICOM_PDU_A_ABORT) {
        b[o++] = type; b[o++] = 0; put32be(b, &o, 4); b[o++] = 0; b[o++] = 0; b[o++] = 2; b[o++] = 0;
    }
    return o;
}


static void dicom_put_uid_item(uint8_t *b, size_t *o, uint8_t item_type, const char *uid) {
    b[(*o)++] = item_type;
    b[(*o)++] = 0;
    put16be(b, o, (uint16_t)strlen(uid));
    put_bytes(b, o, uid, strlen(uid));
}

static void dicom_put_presentation_context(uint8_t *b, size_t *o, uint8_t pcid, const char *abstract_uid, const char **ts, size_t ts_count) {
    b[(*o)++] = 0x20;
    b[(*o)++] = 0;
    size_t len_pos = *o; put16be(b, o, 0);
    size_t start = *o;
    b[(*o)++] = pcid;
    b[(*o)++] = 0; b[(*o)++] = 0; b[(*o)++] = 0;
    dicom_put_uid_item(b, o, 0x30, abstract_uid);
    for (size_t i = 0; i < ts_count; i++) dicom_put_uid_item(b, o, 0x40, ts[i]);
    uint16_t item_len = (uint16_t)(*o - start);
    b[len_pos] = (uint8_t)(item_len >> 8);
    b[len_pos + 1] = (uint8_t)item_len;
}

static void dicom_put_wide_presentation_context(uint8_t *b, size_t *o, uint8_t pcid) {
    b[(*o)++] = 0x20;
    b[(*o)++] = 0;
    size_t len_pos = *o; put16be(b, o, 0);
    size_t start = *o;
    b[(*o)++] = pcid;
    b[(*o)++] = 0; b[(*o)++] = 0; b[(*o)++] = 0;
    dicom_put_uid_item(b, o, 0x30, "1.2.840.10008.1.1");
    for (size_t i = 0; i < DICOM_MAX_TRANSFER_SYNTAXES + 2; i++) {
        dicom_put_uid_item(b, o, 0x40, (i & 1) ? "1.2.840.10008.1.2.1" : "1.2.840.10008.1.2");
    }
    b[(*o)++] = 0x41;
    b[(*o)++] = 0;
    put16be(b, o, 3);
    b[(*o)++] = 0xaa; b[(*o)++] = 0xbb; b[(*o)++] = 0xcc;
    uint16_t item_len = (uint16_t)(*o - start);
    b[len_pos] = (uint8_t)(item_len >> 8);
    b[len_pos + 1] = (uint8_t)item_len;
}

static size_t make_dicom_associate_rq_rich(uint8_t *b) {
    size_t o = 0;
    b[o++] = DICOM_PDU_A_ASSOCIATE_RQ;
    b[o++] = 0;
    size_t len_pos = o; put32be(b, &o, 0);
    size_t start = o;
    put16be(b, &o, 1); put16be(b, &o, 0);
    memset(b + o, ' ', 16); memcpy(b + o, "DCM4CHEE", 7); o += 16;
    memset(b + o, ' ', 16); memcpy(b + o, "LEMURSCU", 8); o += 16;
    memset(b + o, 0, 32); o += 32;
    dicom_put_uid_item(b, &o, 0x10, "1.2.840.10008.3.1.1.1");
    const char *ts1[] = {"1.2.840.10008.1.2", "1.2.840.10008.1.2.1"};
    dicom_put_presentation_context(b, &o, 1, "1.2.840.10008.1.1", ts1, 2);
    const char *ts2[] = {"1.2.840.10008.1.2.1"};
    dicom_put_presentation_context(b, &o, 3, "1.2.840.10008.5.1.4.1.1.2", ts2, 1);
    b[o++] = 0x50; b[o++] = 0;
    size_t ui_len_pos = o; put16be(b, &o, 0);
    size_t ui_start = o;
    b[o++] = 0x51; b[o++] = 0; put16be(b, &o, 4); put32be(b, &o, 16384);
    dicom_put_uid_item(b, &o, 0x52, "1.2.826.0.1.3680043.10.543.1");
    b[o++] = 0x53; b[o++] = 0; put16be(b, &o, 4); put16be(b, &o, 1); put16be(b, &o, 1);
    for (size_t i = 0; i < DICOM_MAX_ROLE_SELECTIONS + 1; i++) {
        const char *role_uid = (i & 1) ? "1.2.840.10008.5.1.4.1.1.2" : "1.2.840.10008.1.1";
        size_t role_uid_len = strlen(role_uid);
        b[o++] = 0x54;
        b[o++] = 0;
        put16be(b, &o, (uint16_t)(2 + role_uid_len + 2));
        put16be(b, &o, (uint16_t)role_uid_len);
        put_bytes(b, &o, role_uid, role_uid_len);
        b[o++] = 1;
        b[o++] = (uint8_t)((i & 1) ? 1 : 0);
    }
    dicom_put_uid_item(b, &o, 0x55, "LEMUR_1");
    b[o++] = 0x59; b[o++] = 0; put16be(b, &o, 3); b[o++] = 0xaa; b[o++] = 0xbb; b[o++] = 0xcc;
    uint16_t ui_len = (uint16_t)(o - ui_start);
    b[ui_len_pos] = (uint8_t)(ui_len >> 8); b[ui_len_pos + 1] = (uint8_t)ui_len;
    uint32_t pdu_len = (uint32_t)(o - start);
    b[len_pos] = (uint8_t)(pdu_len >> 24);
    b[len_pos + 1] = (uint8_t)(pdu_len >> 16);
    b[len_pos + 2] = (uint8_t)(pdu_len >> 8);
    b[len_pos + 3] = (uint8_t)pdu_len;
    return o;
}


static void dicom_put_presentation_context_ac(uint8_t *b, size_t *o, uint8_t pcid, uint8_t result, const char *transfer_uid) {
    b[(*o)++] = 0x21;
    b[(*o)++] = 0;
    size_t len_pos = *o; put16be(b, o, 0);
    size_t start = *o;
    b[(*o)++] = pcid;
    b[(*o)++] = 0;
    b[(*o)++] = result;
    b[(*o)++] = 0;
    dicom_put_uid_item(b, o, 0x40, transfer_uid);
    uint16_t item_len = (uint16_t)(*o - start);
    b[len_pos] = (uint8_t)(item_len >> 8);
    b[len_pos + 1] = (uint8_t)item_len;
}

static size_t make_dicom_associate_ac_rich(uint8_t *b) {
    size_t o = 0;
    b[o++] = DICOM_PDU_A_ASSOCIATE_AC;
    b[o++] = 0;
    size_t len_pos = o; put32be(b, &o, 0);
    size_t start = o;
    put16be(b, &o, 1);
    put16be(b, &o, 0);
    memset(b + o, ' ', 16); memcpy(b + o, "DCM4CHEE", 7); o += 16;
    memset(b + o, ' ', 16); memcpy(b + o, "LEMURSCU", 8); o += 16;
    memset(b + o, 0, 32); o += 32;
    dicom_put_uid_item(b, &o, 0x10, "1.2.840.10008.3.1.1.1");
    dicom_put_presentation_context_ac(b, &o, 1, 0, "1.2.840.10008.1.2.1");
    dicom_put_presentation_context_ac(b, &o, 3, 2, "1.2.840.10008.1.2");
    b[o++] = 0x50; b[o++] = 0;
    size_t ui_len_pos = o; put16be(b, &o, 0);
    size_t ui_start = o;
    b[o++] = 0x51; b[o++] = 0; put16be(b, &o, 4); put32be(b, &o, 32768);
    dicom_put_uid_item(b, &o, 0x52, "1.2.826.0.1.3680043.10.543.2");
    dicom_put_uid_item(b, &o, 0x55, "LEMUR_ACCEPTOR");
    uint16_t ui_len = (uint16_t)(o - ui_start);
    b[ui_len_pos] = (uint8_t)(ui_len >> 8);
    b[ui_len_pos + 1] = (uint8_t)ui_len;
    b[o++] = 0x5a; b[o++] = 0; put16be(b, &o, 1); b[o++] = 0xff;
    uint32_t pdu_len = (uint32_t)(o - start);
    b[len_pos] = (uint8_t)(pdu_len >> 24);
    b[len_pos + 1] = (uint8_t)(pdu_len >> 16);
    b[len_pos + 2] = (uint8_t)(pdu_len >> 8);
    b[len_pos + 3] = (uint8_t)pdu_len;
    return o;
}

static size_t make_dicom_multi_pdv_pdata(uint8_t *b) {
    uint8_t cmdset[1024]; size_t co = 0;
    dicom_put_elem_text(cmdset, &co, 0x0002, "1.2.840.10008.1.1");
    dicom_put_elem_u16(cmdset, &co, 0x0100, DICOM_DIMSE_C_STORE_RQ);
    dicom_put_elem_u16(cmdset, &co, 0x0110, 7);
    dicom_put_elem_u16(cmdset, &co, 0x0700, 0);
    dicom_put_elem_u16(cmdset, &co, 0x0800, 0);
    dicom_put_elem_text(cmdset, &co, 0x1000, "1.2.3.4.7");
    uint8_t dataset[32]; size_t ds = 0;
    for (int i = 0; i < 32; i++) dataset[ds++] = (uint8_t)(0x80 + i);
    size_t o = 0;
    b[o++] = DICOM_PDU_P_DATA_TF; b[o++] = 0;
    size_t len_pos = o; put32be(b, &o, 0);
    put32be(b, &o, (uint32_t)(2 + co));
    b[o++] = 1;
    b[o++] = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
    put_bytes(b, &o, cmdset, co);
    put32be(b, &o, (uint32_t)(2 + ds));
    b[o++] = 1;
    b[o++] = DICOM_PDV_FLAG_LAST_FRAGMENT;
    put_bytes(b, &o, dataset, ds);
    uint32_t pdu_len = (uint32_t)(o - (len_pos + 4));
    b[len_pos] = (uint8_t)(pdu_len >> 24);
    b[len_pos + 1] = (uint8_t)(pdu_len >> 16);
    b[len_pos + 2] = (uint8_t)(pdu_len >> 8);
    b[len_pos + 3] = (uint8_t)pdu_len;
    return o;
}

static size_t make_dicom_response_like_pdata(uint8_t *b) {
    uint8_t cmdset[512]; size_t co = 0;
    dicom_put_elem_text(cmdset, &co, 0x0002, "1.2.840.10008.1.1");
    dicom_put_elem_u16(cmdset, &co, 0x0100, 0x8030); /* C-ECHO-RSP, parser/reassembler reachability only */
    dicom_put_elem_u16(cmdset, &co, 0x0120, 7);
    dicom_put_elem_u16(cmdset, &co, 0x0800, 0x0101);
    dicom_put_elem_u16(cmdset, &co, 0x0900, 0);
    size_t o = 0;
    b[o++] = DICOM_PDU_P_DATA_TF; b[o++] = 0;
    size_t len_pos = o; put32be(b, &o, 0);
    put32be(b, &o, (uint32_t)(2 + co));
    b[o++] = 1;
    b[o++] = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
    put_bytes(b, &o, cmdset, co);
    uint32_t pdu_len = (uint32_t)(o - (len_pos + 4));
    b[len_pos] = (uint8_t)(pdu_len >> 24);
    b[len_pos + 1] = (uint8_t)(pdu_len >> 16);
    b[len_pos + 2] = (uint8_t)(pdu_len >> 8);
    b[len_pos + 3] = (uint8_t)pdu_len;
    return o;
}

static size_t make_dicom_association_and_data(uint8_t *b) {
    size_t o = make_dicom_associate_rq_rich(b);
    o += make_dicom_multi_pdv_pdata(b + o);
    o += make_dicom_simple_pdu(b + o, DICOM_PDU_A_RELEASE_RQ);
    return o;
}

static void sanity_dicom(void) {
    uint8_t buf[8192], out[8192];
    static dicom_packet_t pkts[4], reparsed[4];
    const uint8_t pdus[] = {1,2,3,5,6,7};
    for (size_t i = 0; i < sizeof(pdus); i++) {
        size_t len = make_dicom_simple_pdu(buf, pdus[i]);
        check_dicom_metamorphic(buf, len, "DICOM PDU seed", 0);
        check_dicom_metamorphic(buf, len, "DICOM PDU seed", 1);
        memset(pkts, 0, sizeof(pkts)); memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_dicom_msg(buf, (u32)len, pkts, 2);
        CHECK(n == 1, "DICOM parse PS3.8 PDU");
        if (n != 1) continue;
        fix_dicom(pkts, (int)n);
        u32 out_len = sizeof(out);
        CHECK(reassemble_dicom_msgs(pkts, (u32)n, out, &out_len) == 0, "DICOM reassemble PDU");
        CHECK(parse_dicom_msg(out, out_len, reparsed, 2) == 1, "DICOM parse PDU after reassemble");
    }
    const uint16_t cmds[] = {
        DICOM_DIMSE_C_STORE_RQ, DICOM_DIMSE_C_GET_RQ, DICOM_DIMSE_C_FIND_RQ,
        DICOM_DIMSE_C_MOVE_RQ, DICOM_DIMSE_C_ECHO_RQ, DICOM_DIMSE_N_EVENT_REPORT_RQ,
        DICOM_DIMSE_N_GET_RQ, DICOM_DIMSE_N_SET_RQ, DICOM_DIMSE_N_ACTION_RQ,
        DICOM_DIMSE_N_CREATE_RQ, DICOM_DIMSE_N_DELETE_RQ, DICOM_DIMSE_C_CANCEL_RQ
    };
    for (size_t i = 0; i < sizeof(cmds)/sizeof(cmds[0]); i++) {
        size_t len = make_dicom_dimse_pdata(buf, cmds[i]);
        check_dicom_metamorphic(buf, len, "DICOM DIMSE seed", 0);
        check_dicom_metamorphic(buf, len, "DICOM DIMSE seed", 1);
        memset(pkts, 0, sizeof(pkts)); memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_dicom_msg(buf, (u32)len, pkts, 2);
        CHECK(n == 1, "DICOM parse DIMSE request");
        if (n != 1) continue;
        CHECK(pkts[0].u.p_data_tf.pdvs[0].has_dimse_command, "DICOM DIMSE command recognized");
        CHECK(pkts[0].u.p_data_tf.pdvs[0].dimse_command_field == cmds[i], "DICOM DIMSE command field parsed");
        fix_dicom(pkts, (int)n);
        u32 out_len = sizeof(out);
        CHECK(reassemble_dicom_msgs(pkts, (u32)n, out, &out_len) == 0, "DICOM reassemble DIMSE");
        size_t rn = parse_dicom_msg(out, out_len, reparsed, 2);
        CHECK(rn == 1, "DICOM parse DIMSE after reassemble");
        if (rn == 1) CHECK(reparsed[0].u.p_data_tf.pdvs[0].dimse_command_field == cmds[i], "DICOM DIMSE type preserved");
    }

    {
        size_t len = make_dicom_associate_rq_rich(buf);
        check_dicom_metamorphic(buf, len, "DICOM rich association", 0);
        check_dicom_metamorphic(buf, len, "DICOM rich association", 1);
    }
    {
        size_t len = make_dicom_associate_ac_rich(buf);
        check_dicom_metamorphic(buf, len, "DICOM rich association accept", 0);
        check_dicom_metamorphic(buf, len, "DICOM rich association accept", 1);
    }
    {
        size_t len = make_dicom_multi_pdv_pdata(buf);
        check_dicom_metamorphic(buf, len, "DICOM multi PDV", 0);
        check_dicom_metamorphic(buf, len, "DICOM multi PDV", 1);
    }
    {
        size_t len = make_dicom_response_like_pdata(buf);
        check_dicom_metamorphic(buf, len, "DICOM response-like DIMSE", 0);
    }
    {
        size_t len = make_dicom_association_and_data(buf);
        check_dicom_metamorphic(buf, len, "DICOM association plus data", 0);
        check_dicom_metamorphic(buf, len, "DICOM association plus data", 1);
    }
    {
        size_t a_len = make_dicom_simple_pdu(buf, DICOM_PDU_A_ASSOCIATE_RQ);
        size_t p_len = make_dicom_dimse_pdata(buf + a_len, DICOM_DIMSE_C_ECHO_RQ);
        buf[a_len + 10] = 5; /* deliberately not negotiated by the RQ */
        buf[a_len + 11] = DICOM_PDV_FLAG_COMMAND; /* deliberately missing LAST_FRAGMENT */
        memset(pkts, 0, sizeof(pkts)); memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_dicom_msg(buf, (u32)(a_len + p_len), pkts, 4);
        CHECK(n == 2, "DICOM parse association plus P-DATA");
        if (n == 2) {
            fix_dicom(pkts, (int)n);
            u32 out_len = sizeof(out);
            CHECK(reassemble_dicom_msgs(pkts, (u32)n, out, &out_len) == 0, "DICOM reassemble fixed association plus P-DATA");
            size_t rn = parse_dicom_msg(out, out_len, reparsed, 4);
            CHECK(rn == 2, "DICOM parse fixed association plus P-DATA");
            if (rn == 2) {
                uint8_t fixed_pcid = reparsed[1].u.p_data_tf.pdvs[0].presentation_context_id;
                CHECK((fixed_pcid & 1u) != 0 && fixed_pcid != 0, "DICOM fixer keeps P-DATA PCID odd/nonzero");
                CHECK(reparsed[0].u.a_associate_rq.presentation_contexts[0].presentation_context_id == fixed_pcid, "DICOM fixer negotiates P-DATA PCID in association");
                CHECK((reparsed[1].u.p_data_tf.pdvs[0].control_header & DICOM_PDV_FLAG_LAST_FRAGMENT) != 0, "DICOM fixer sets PDV last fragment");
                CHECK((reparsed[1].u.p_data_tf.pdvs[0].control_header & DICOM_PDV_FLAG_COMMAND) != 0, "DICOM fixer preserves command PDV");
            }
        }
    }

    {
        const size_t payload_len = 4096;
        size_t o = 0;
        buf[o++] = DICOM_PDU_P_DATA_TF;
        buf[o++] = 0;
        put32be(buf, &o, (uint32_t)(4 + 2 + payload_len));
        put32be(buf, &o, (uint32_t)(2 + payload_len));
        buf[o++] = 1;
        buf[o++] = DICOM_PDV_FLAG_LAST_FRAGMENT;
        for (size_t j = 0; j < payload_len; j++) buf[o++] = (uint8_t)(j & 0xff);
        memset(pkts, 0, sizeof(pkts)); memset(reparsed, 0, sizeof(reparsed));
        size_t n = parse_dicom_msg(buf, (u32)o, pkts, 2);
        CHECK(n == 1, "DICOM parse large data PDV");
        if (n == 1) {
            CHECK(pkts[0].u.p_data_tf.pdvs[0].data_length == payload_len, "DICOM large PDV length preserved by parser");
            fix_dicom(pkts, (int)n);
            u32 out_len = sizeof(out);
            CHECK(reassemble_dicom_msgs(pkts, (u32)n, out, &out_len) == 0, "DICOM reassemble large data PDV");
            size_t rn = parse_dicom_msg(out, out_len, reparsed, 2);
            CHECK(rn == 1, "DICOM parse large data PDV after reassemble");
            if (rn == 1) {
                CHECK(reparsed[0].u.p_data_tf.pdvs[0].data_length == payload_len, "DICOM large PDV length preserved after reassemble");
                CHECK(reparsed[0].u.p_data_tf.pdvs[0].data[payload_len - 1] == (uint8_t)((payload_len - 1) & 0xff), "DICOM large PDV last byte preserved");
            }
        }
    }
}


static size_t make_dns_many_sections(uint8_t *b) {
    size_t o = 0;
    put16be(b, &o, 0x4444);
    put16be(b, &o, 0x0100);
    put16be(b, &o, DNS_MAX_QUESTIONS + 1);
    put16be(b, &o, DNS_MAX_RRS + 1);
    put16be(b, &o, DNS_MAX_RRS + 1);
    put16be(b, &o, DNS_MAX_RRS + 1);
    for (int i = 0; i < DNS_MAX_QUESTIONS + 1; i++) {
        b[o++] = 0; put16be(b, &o, 1); put16be(b, &o, 1);
    }
    for (int section = 0; section < 3; section++) {
        for (int i = 0; i < DNS_MAX_RRS + 1; i++) {
            b[o++] = 0; put16be(b, &o, 1); put16be(b, &o, 1); put32be(b, &o, 1); put16be(b, &o, 4);
            b[o++] = 192; b[o++] = 0; b[o++] = (uint8_t)section; b[o++] = (uint8_t)i;
        }
    }
    return o;
}


static size_t make_dns_tsig_query(uint8_t *b) {
    size_t o = 0;
    put16be(b, &o, 0x2845);
    put16be(b, &o, 0x0100);
    put16be(b, &o, 1);
    put16be(b, &o, 0);
    put16be(b, &o, 0);
    put16be(b, &o, 1);
    put_dns_name(b, &o, "example", "com"); put16be(b, &o, 1); put16be(b, &o, 1);
    put_dns_name(b, &o, "sig", "example");
    put16be(b, &o, 250);
    put16be(b, &o, 255);
    put32be(b, &o, 0);
    size_t rdlen_pos = o; put16be(b, &o, 0);
    size_t rstart = o;
    b[o++] = 11; put_bytes(b, &o, "hmac-sha256", 11); b[o++] = 0;
    b[o++] = 0; b[o++] = 0; b[o++] = 1; b[o++] = 2; b[o++] = 3; b[o++] = 4;
    put16be(b, &o, 300);
    put16be(b, &o, 4); b[o++] = 0xaa; b[o++] = 0xbb; b[o++] = 0xcc; b[o++] = 0xdd;
    put16be(b, &o, 0x2845);
    put16be(b, &o, 0);
    put16be(b, &o, 2); b[o++] = 0x12; b[o++] = 0x34;
    uint16_t rdlen = (uint16_t)(o - rstart);
    b[rdlen_pos] = (uint8_t)(rdlen >> 8);
    b[rdlen_pos + 1] = (uint8_t)rdlen;
    return o;
}

static void exercise_dns_coverage_edges(void) {
    static uint8_t buf[65536], out[65536];
    size_t len = make_dns_many_sections(buf);
    memset(dns_rt1, 0, sizeof(dns_rt1));
    CHECK(parse_dns_msg(buf, (u32)len, dns_rt1, 1) == 1, "DNS over-capacity framing parsed");
    CHECK(dns_rt1[0].u.dns_message.capacity_exceeded, "DNS over-capacity marked incomplete");
    u32 cap = sizeof(out);
    CHECK(reassemble_dns_msgs(dns_rt1, 1, out, &cap) == 0 && cap == len && !memcmp(buf, out, len),
          "DNS over-capacity exact cached reassembly");
    dns_rt1[0].u.dns_message.wire_len = 0;
    cap = sizeof(out);
    CHECK(reassemble_dns_msgs(dns_rt1, 1, out, &cap) == 0 && cap == len && !memcmp(buf, out, len),
          "DNS over-capacity exact field and tail reassembly");
    uint8_t invalid_name[] = {0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0,4,'t','e'};
    (void)parse_dns_msg(invalid_name, sizeof(invalid_name), dns_rt1, 4);
    uint8_t unterminated_name[] = {0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0,1,'a'};
    (void)parse_dns_msg(unterminated_name, sizeof(unterminated_name), dns_rt1, 4);
    size_t dso = 0;
    put16be(buf, &dso, 0x8490); put16be(buf, &dso, (uint16_t)(6u << 11));
    put16be(buf, &dso, 1); put16be(buf, &dso, 0); put16be(buf, &dso, 0); put16be(buf, &dso, 0);
    put16be(buf, &dso, 1); put16be(buf, &dso, 0);
    CHECK(parse_dns_msg(buf, (u32)dso, dns_rt1, 4) == 1, "DNS DSO nonzero count parsed");
    CHECK(dns_rt1[0].u.dns_message.capacity_exceeded, "DNS DSO nonzero count marked");
    dso = 0;
    put16be(buf, &dso, 0x8491); put16be(buf, &dso, (uint16_t)(6u << 11));
    put16be(buf, &dso, 0); put16be(buf, &dso, 0); put16be(buf, &dso, 0); put16be(buf, &dso, 0);
    for (int i = 0; i < DNS_MAX_DSO_TLVS + 1; i++) { put16be(buf, &dso, (uint16_t)i); put16be(buf, &dso, 0); }
    CHECK(parse_dns_msg(buf, (u32)dso, dns_rt1, 4) == 1, "DNS DSO over max TLVs parsed");
    CHECK(dns_rt1[0].u.dns_message.capacity_exceeded, "DNS DSO over max TLVs marked");
    size_t typed = 0;
    put16be(buf, &typed, 0x4445); put16be(buf, &typed, 0x8180);
    put16be(buf, &typed, 1); put16be(buf, &typed, 2); put16be(buf, &typed, 0); put16be(buf, &typed, 0);
    put_dns_name(buf, &typed, "svc", "example"); put16be(buf, &typed, 33); put16be(buf, &typed, 1);
    put16be(buf, &typed, 0xc00c); put16be(buf, &typed, 28); put16be(buf, &typed, 1); put32be(buf, &typed, 60); put16be(buf, &typed, 16);
    for (int ai = 0; ai < 16; ai++) buf[typed++] = (uint8_t)ai;
    put16be(buf, &typed, 0xc00c); put16be(buf, &typed, 33); put16be(buf, &typed, 1); put32be(buf, &typed, 60);
    size_t srv_len_pos = typed; put16be(buf, &typed, 0);
    size_t srv_start = typed; put16be(buf, &typed, 10); put16be(buf, &typed, 20); put16be(buf, &typed, 443); put_dns_name(buf, &typed, "target", "example");
    buf[srv_len_pos] = (uint8_t)((typed - srv_start) >> 8); buf[srv_len_pos + 1] = (uint8_t)(typed - srv_start);
    CHECK(parse_dns_msg(buf, (u32)typed, dns_rt1, 4) == 1, "DNS typed AAAA/SRV RDATA parsed");
    CHECK(dns_rt1[0].u.dns_message.answers[0].rdata_schema == 28, "DNS AAAA typed RDATA view");
    size_t tsig_len = make_dns_tsig_query(buf);
    check_dns_metamorphic(buf, tsig_len, "DNS TSIG RFC2845", 0);
    check_dns_metamorphic(buf, tsig_len, "DNS TSIG RFC2845", 1);
    CHECK(parse_dns_msg(buf, (u32)tsig_len, dns_rt1, 4) == 1, "DNS TSIG parsed");
    CHECK(dns_rt1[0].u.dns_message.additionals[0].rdata_schema == 250, "DNS TSIG typed RDATA view");
    CHECK(dns_rt1[0].u.dns_message.additionals[0].has_tsig, "DNS TSIG typed fields present");
    CHECK(dns_rt1[0].u.dns_message.additionals[0].tsig_mac_len == 4, "DNS TSIG MAC length parsed");
    CHECK(dns_rt1[0].u.dns_message.additionals[0].tsig_other_len == 2, "DNS TSIG other length parsed");

    dns_packet_t p; u32 out_len;
    memset(&p, 0, sizeof(p)); p.type = DNS_HEADER; p.u.dns_header.packet_type = DNS_HEADER; p.u.dns_header.id = 1;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS direct header reassemble");
    memset(&p, 0, sizeof(p)); p.type = DNS_QUESTION; p.u.dns_question.packet_type = DNS_QUESTION; p.u.dns_question.qtype = 1; p.u.dns_question.qclass = 1;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS direct question reassemble");
    memset(&p, 0, sizeof(p)); p.type = DNS_RESOURCE_RECORD; p.u.dns_rr.packet_type = DNS_RESOURCE_RECORD; p.u.dns_rr.name[0] = 0; p.u.dns_rr.name_len = 1; p.u.dns_rr.type = 1; p.u.dns_rr.class_code = 1; p.u.dns_rr.rdata_len = 4; p.u.dns_rr.rdlength = 4;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS direct RR reassemble");
    memset(&p, 0, sizeof(p)); p.type = DNS_OPT_RECORD; p.u.dns_opt.packet_type = DNS_OPT_RECORD; p.u.dns_opt.name[0] = 0; p.u.dns_opt.name_len = 1; p.u.dns_opt.type = 41; p.u.dns_opt.udp_payload_size = 1232;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS direct OPT reassemble");
    memset(&p, 0, sizeof(p)); p.type = DNS_OPAQUE_RDATA; p.u.dns_opaque.packet_type = DNS_OPAQUE_RDATA; p.u.dns_opaque.rdlength = 3; p.u.dns_opaque.rdata_len = 3; p.u.dns_opaque.rdata[0] = 1;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS direct opaque rdata reassemble");
    memset(&p, 0, sizeof(p)); p.type = DNS_MESSAGE; p.u.dns_message.header.id = 2; p.u.dns_message.answer_count = 1; p.u.dns_message.answers[0].ttl = 9;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS RR present via ttl reassemble");
    memset(&p, 0, sizeof(p)); p.type = DNS_QUESTION; p.u.dns_question.packet_type = DNS_QUESTION; p.u.dns_question.name_len = 2; p.u.dns_question.name[0] = 1; p.u.dns_question.name[1] = 'a'; p.u.dns_question.qtype = 1; p.u.dns_question.qclass = 1;
    out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) == 0, "DNS invalid direct name writes root");
    memset(&p, 0, sizeof(p)); p.type = 99; out_len = sizeof(out); CHECK(reassemble_dns_msgs(&p, 1, out, &out_len) != 0, "DNS invalid packet type rejected");
}

static void exercise_ssh_coverage_edges(void) {
    static uint8_t wire[70000], payload[70000], out[70000];
    const char *bad_banner = "SSH-1.99-old\r\n";
    check_ssh_metamorphic((const uint8_t*)bad_banner, strlen(bad_banner), "SSH non-2 banner opaque", 0);
    uint8_t raw[] = {0xde,0xad,0xbe,0xef,0x01,0x02};
    check_ssh_metamorphic(raw, sizeof(raw), "SSH opaque raw", 0);

    size_t o = 0;
    payload[o++] = SSH_MSG_DISCONNECT;
    put32be(payload, &o, 11);
    ssh_put_cstring(payload, &o, "disconnect");
    ssh_put_cstring(payload, &o, "en");
    payload[o++] = 0xaa; payload[o++] = 0xbb;
    size_t wlen = wrap_ssh_packet(wire, payload, o);
    check_ssh_metamorphic(wire, wlen, "SSH typed trailing payload", 0);

    o = 0; payload[o++] = 200; payload[o++] = 1;
    wlen = wrap_ssh_packet(wire, payload, o);
    check_ssh_metamorphic(wire, wlen, "SSH unknown transport code", 0);

    ssh_packet_t pkt; u32 out_len;
    memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_BANNER; memcpy(pkt.u.banner.software, "LEMUR", 5); pkt.u.banner.software_len = 5; pkt.u.banner.has_comments = 1; memcpy(pkt.u.banner.comments, "comment", 7); pkt.u.banner.comments_len = 7;
    out_len = sizeof(out); CHECK(reassemble_ssh_msgs(&pkt, 1, out, &out_len) == 0, "SSH constructed banner reassemble");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_TRANSPORT_PACKET; pkt.u.transport.packet_length = 8; pkt.u.transport.padding_length = 6; pkt.u.transport.payload_len = 1; pkt.u.transport.payload[0] = 200;
    out_len = sizeof(out); CHECK(reassemble_ssh_msgs(&pkt, 1, out, &out_len) == 0, "SSH direct transport reassemble");
    ssh_packet_type_t types[] = {SSH_DISCONNECT,SSH_IGNORE,SSH_UNIMPLEMENTED,SSH_DEBUG,SSH_SERVICE_ACCEPT,SSH_KEXDH_REPLY,SSH_KEX_DH_GEX_INIT,SSH_KEX_DH_GEX_REQUEST,SSH_USERAUTH_REQUEST,SSH_USERAUTH_FAILURE,SSH_USERAUTH_SUCCESS,SSH_USERAUTH_BANNER,SSH_USERAUTH_METHOD_REPLY,SSH_USERAUTH_INFO_RESPONSE,SSH_GLOBAL_REQUEST,SSH_REQUEST_SUCCESS,SSH_REQUEST_FAILURE,SSH_CHANNEL_OPEN,SSH_CHANNEL_OPEN_CONFIRMATION,SSH_CHANNEL_OPEN_FAILURE,SSH_CHANNEL_WINDOW_ADJUST,SSH_CHANNEL_DATA,SSH_CHANNEL_EXTENDED_DATA,SSH_CHANNEL_EOF,SSH_CHANNEL_CLOSE,SSH_CHANNEL_REQUEST,SSH_CHANNEL_SUCCESS,SSH_CHANNEL_FAILURE};
    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        memset(&pkt, 0, sizeof(pkt)); pkt.type = types[i]; pkt.u.typed.message_code = 0; pkt.u.typed.payload_len = 0; pkt.u.typed.field_schema = 0;
        out_len = sizeof(out); CHECK(reassemble_ssh_msgs(&pkt, 1, out, &out_len) == 0, "SSH default message code reassemble");
    }
    memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_CHANNEL_REQUEST; pkt.u.typed.field_schema = SSH_MSG_CHANNEL_REQUEST; pkt.u.typed.message_code = SSH_MSG_CHANNEL_REQUEST; pkt.u.typed.uint32_count = 1; pkt.u.typed.uint32_values[0] = 7; pkt.u.typed.boolean_value = 1; pkt.u.typed.boolean_count = 0; pkt.u.typed.string_count = 1; pkt.u.typed.strings[0].len = 8; memcpy(pkt.u.typed.strings[0].bytes, "xon-xoff", 8);
    out_len = sizeof(out); CHECK(reassemble_ssh_msgs(&pkt, 1, out, &out_len) == 0, "SSH bool fallback channel request reassemble");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = SSH_IGNORE; pkt.u.typed.message_code = 250; pkt.u.typed.field_schema = 250;
    out_len = sizeof(out); CHECK(reassemble_ssh_msgs(&pkt, 1, out, &out_len) != 0, "SSH unknown structured message code rejected");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = (ssh_packet_type_t)255; out_len = sizeof(out); CHECK(reassemble_ssh_msgs(&pkt, 1, out, &out_len) != 0, "SSH invalid packet type rejected");
}

static void exercise_tls_coverage_edges(void) {
    static uint8_t buf[8192], out[8192];
    size_t len = make_tls_record(buf, TLS_CONTENTTYPE_HANDSHAKE, TLS_HANDSHAKE_CLIENT_HELLO);
    /* Strip the two-byte extensions length from the minimal ClientHello to cover no-extensions parsing. */
    if (len >= 2) {
        uint16_t rec_len = (uint16_t)((buf[3] << 8) | buf[4]);
        if (rec_len >= 2) { rec_len -= 2; buf[3] = (uint8_t)(rec_len >> 8); buf[4] = (uint8_t)rec_len; }
        uint32_t hs_len = ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 8) | buf[8];
        if (hs_len >= 2) { hs_len -= 2; buf[6] = (uint8_t)(hs_len >> 16); buf[7] = (uint8_t)(hs_len >> 8); buf[8] = (uint8_t)hs_len; }
        len -= 2;
        check_tls_metamorphic(buf, len, "TLS ClientHello no extensions", 0);
    }
    uint8_t unknown_record[] = {99,3,3,0,0};
    (void)parse_tls_msg(unknown_record, sizeof(unknown_record), tls_rt1, 4);
    tls_packet_t pkt; u32 out_len;
    uint8_t hsbody[] = {TLS_HANDSHAKE_FINISHED,0,0,3,1,2,3};
    size_t to = 0;
    buf[to++] = TLS_CONTENTTYPE_HANDSHAKE; buf[to++] = 3; buf[to++] = 4; put16be(buf, &to, 0);
    buf[to++] = TLS_HANDSHAKE_CERTIFICATE; put24be(buf, &to, 13);
    buf[to++] = 3; put_bytes(buf, &to, "ctx", 3); put24be(buf, &to, 6); put24be(buf, &to, 1); buf[to++] = 0xaa; put16be(buf, &to, 0);
    buf[3] = 0; buf[4] = (uint8_t)(to - 5);
    CHECK(parse_tls_msg(buf, (u32)to, tls_rt1, 4) == 1, "TLS 1.3 certificate typed parse");
    to = 0;
    buf[to++] = TLS_CONTENTTYPE_HANDSHAKE; buf[to++] = 3; buf[to++] = 3; put16be(buf, &to, 10);
    buf[to++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY; put24be(buf, &to, 6); put16be(buf, &to, 0x0401); put16be(buf, &to, 999); buf[to++] = 1; buf[to++] = 2;
    CHECK(parse_tls_msg(buf, (u32)to, tls_rt1, 4) == 1, "TLS certificate verify fallback typed parse");
    uint8_t full_hs[256];
    size_t full_len = make_tls_record(full_hs, TLS_CONTENTTYPE_HANDSHAKE, TLS_HANDSHAKE_CLIENT_HELLO);
    uint16_t full_frag_len = (uint16_t)((full_hs[3] << 8) | full_hs[4]);
    to = 0;
    buf[to++] = TLS_CONTENTTYPE_HANDSHAKE; buf[to++] = 3; buf[to++] = 3; put16be(buf, &to, 5);
    put_bytes(buf, &to, full_hs + 5, 5);
    buf[to++] = TLS_CONTENTTYPE_HANDSHAKE; buf[to++] = 3; buf[to++] = 3; put16be(buf, &to, (uint16_t)(full_frag_len - 5 + 4));
    put_bytes(buf, &to, full_hs + 10, full_frag_len - 5);
    buf[to++] = TLS_HANDSHAKE_FINISHED; put24be(buf, &to, 0);
    CHECK(parse_tls_msg(buf, (u32)to, tls_rt1, 4) == 2, "TLS fragmented handshake with trailing coalesced parse");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = TLS_PACKET_HANDSHAKE; pkt.u.handshake.record.type = TLS_CONTENTTYPE_HANDSHAKE; pkt.u.handshake.record.version.major = 3; pkt.u.handshake.record.version.minor = 3; pkt.u.handshake.handshake.msg_type = TLS_HANDSHAKE_FINISHED; pkt.u.handshake.handshake.length.b2 = 3; pkt.u.handshake.handshake.body = hsbody; pkt.u.handshake.handshake.body_len = sizeof(hsbody);
    out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) == 0, "TLS direct handshake body copy");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = TLS_PACKET_HANDSHAKE; pkt.u.handshake.record.type = TLS_CONTENTTYPE_HANDSHAKE; pkt.u.handshake.record.version.major = 3; pkt.u.handshake.record.version.minor = 3; pkt.u.handshake.handshake.msg_type = TLS_HANDSHAKE_FINISHED; pkt.u.handshake.handshake.length.b2 = 3; pkt.u.handshake.handshake.body = NULL; pkt.u.handshake.handshake.body_len = 0;
    out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) == 0, "TLS direct handshake zero-fill");
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = TLS_PACKET_HANDSHAKE;
    pkt.u.handshake.record.type = TLS_CONTENTTYPE_HANDSHAKE;
    pkt.u.handshake.record.version.major = 3;
    pkt.u.handshake.record.version.minor = 3;
    pkt.u.handshake.handshake.msg_type = TLS_HANDSHAKE_CERTIFICATE;
    pkt.u.handshake.body_schema = TLS_HANDSHAKE_BODY_CERTIFICATE;
    pkt.u.handshake.body.certificate.tls13_layout = 1;
    pkt.u.handshake.body.certificate.request_context_len = 1;
    pkt.u.handshake.body.certificate.request_context[0] = 'x';
    pkt.u.handshake.body.certificate.certificate_count = 1;
    pkt.u.handshake.body.certificate.certificate_len[0] = 1;
    pkt.u.handshake.body.certificate.certificate_bytes[0][0] = 0xaa;
    pkt.u.handshake.body.certificate.certificate_extensions_len[0] = 2;
    out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) == 0, "TLS typed certificate13 reassemble");
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = TLS_PACKET_HANDSHAKE;
    pkt.u.handshake.record.type = TLS_CONTENTTYPE_HANDSHAKE;
    pkt.u.handshake.record.version.major = 3;
    pkt.u.handshake.record.version.minor = 3;
    pkt.u.handshake.handshake.msg_type = TLS_HANDSHAKE_END_OF_EARLY_DATA;
    pkt.u.handshake.body_schema = TLS_HANDSHAKE_BODY_END_OF_EARLY_DATA;
    out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) == 0, "TLS typed end-of-early-data reassemble");
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = TLS_PACKET_HANDSHAKE;
    pkt.u.handshake.record.type = TLS_CONTENTTYPE_HANDSHAKE;
    pkt.u.handshake.record.version.major = 3;
    pkt.u.handshake.record.version.minor = 3;
    pkt.u.handshake.handshake.msg_type = TLS_HANDSHAKE_CLIENT_HELLO;
    pkt.u.handshake.has_client_hello = 1;
    pkt.u.handshake.client_hello.client_version.major = 3;
    pkt.u.handshake.client_hello.client_version.minor = 3;
    pkt.u.handshake.client_hello.cipher_suites_len = 2;
    pkt.u.handshake.client_hello.cipher_suites[0] = 0x00;
    pkt.u.handshake.client_hello.cipher_suites[1] = 0x2f;
    pkt.u.handshake.client_hello.compression_methods_len = 1;
    pkt.u.handshake.client_hello.compression_methods[0] = 0;
    pkt.u.handshake.client_hello.extensions_present = 1;
    pkt.u.handshake.client_hello.extensions_len = 4;
    pkt.u.handshake.client_hello.extensions[0] = 0x00;
    pkt.u.handshake.client_hello.extensions[1] = 0x0a;
    pkt.u.handshake.client_hello.extensions[2] = 0x00;
    pkt.u.handshake.client_hello.extensions[3] = 0x00;
    out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) == 0, "TLS ClientHello raw extension fallback");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = TLS_PACKET_APPLICATION_DATA; pkt.u.application_data.record.type = TLS_CONTENTTYPE_APPLICATION_DATA; pkt.u.application_data.record.version.major = 3; pkt.u.application_data.record.version.minor = 3; pkt.u.application_data.app_data.data = NULL; pkt.u.application_data.app_data.data_len = 5;
    out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) == 0, "TLS direct appdata zero-fill");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = (tls_packet_type_t)255; out_len = sizeof(out); CHECK(reassemble_tls_msgs(&pkt, 1, out, &out_len) != 0, "TLS invalid packet type rejected");
}

static size_t make_dicom_unknown_pdu(uint8_t *b) {
    size_t o = 0; b[o++] = 0x99; b[o++] = 0; put32be(b, &o, 3); b[o++] = 1; b[o++] = 2; b[o++] = 3; return o;
}

static void exercise_dicom_coverage_edges(void) {
    static uint8_t buf[70000], out[70000];
    size_t len = make_dicom_unknown_pdu(buf);
    check_dicom_metamorphic(buf, len, "DICOM unknown PDU", 0);

    len = make_dicom_dimse_pdata(buf, DICOM_DIMSE_N_ACTION_RQ);
    /* Append command status and attribute identifier list into the command PDV by rebuilding a custom packet. */
    uint8_t cmdset[2048]; size_t co = 0;
    dicom_put_elem_text(cmdset, &co, 0x0003, "1.2.840.10008.1.1");
    dicom_put_elem_u16(cmdset, &co, 0x0100, DICOM_DIMSE_N_ACTION_RQ);
    dicom_put_elem_u16(cmdset, &co, 0x0110, 9);
    dicom_put_elem_u16(cmdset, &co, 0x0700, 1);
    dicom_put_elem_u16(cmdset, &co, 0x0800, 0x0101);
    dicom_put_elem_u16(cmdset, &co, 0x0900, 0x1234);
    cmdset[co++] = 0x00; cmdset[co++] = 0x00; cmdset[co++] = 0x34; cmdset[co++] = 0x12; put32le(cmdset, &co, 1); cmdset[co++] = 0x7f;
    cmdset[co++] = 0x00; cmdset[co++] = 0x00; cmdset[co++] = 0x05; cmdset[co++] = 0x10; put32le(cmdset, &co, 4); cmdset[co++] = 0x10; cmdset[co++] = 0; cmdset[co++] = 0x20; cmdset[co++] = 0;
    dicom_put_elem_u16(cmdset, &co, 0x1008, 3);
    size_t o = 0; buf[o++] = DICOM_PDU_P_DATA_TF; buf[o++] = 0; put32be(buf, &o, (uint32_t)(4 + 2 + co)); put32be(buf, &o, (uint32_t)(2 + co)); buf[o++] = 1; buf[o++] = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT; put_bytes(buf, &o, cmdset, co);
    check_dicom_metamorphic(buf, o, "DICOM DIMSE status attrlist", 0);
    check_dicom_metamorphic(buf, o, "DICOM DIMSE status attrlist", 1);

    /* A-ASSOCIATE-RQ with duplicate app context and unknown top-level item. */
    make_dicom_associate_rq_rich(buf);
    uint32_t body_len = (uint32_t)((buf[2]<<24)|(buf[3]<<16)|(buf[4]<<8)|buf[5]);
    size_t end = 6 + body_len;
    dicom_put_uid_item(buf, &end, 0x10, "1.2.840.10008.3.1.1.1");
    buf[end++] = 0x77; buf[end++] = 0; put16be(buf, &end, 2); buf[end++] = 1; buf[end++] = 2;
    body_len = (uint32_t)(end - 6); buf[2]=(uint8_t)(body_len>>24); buf[3]=(uint8_t)(body_len>>16); buf[4]=(uint8_t)(body_len>>8); buf[5]=(uint8_t)body_len;
    check_dicom_metamorphic(buf, end, "DICOM duplicate and unknown association items", 0);

    /* One Presentation Context with too many Transfer Syntax sub-items plus an unknown sub-item. */
    size_t wo = 0;
    buf[wo++] = DICOM_PDU_A_ASSOCIATE_RQ; buf[wo++] = 0; size_t wlen_pos = wo; put32be(buf, &wo, 0);
    size_t wstart = wo;
    put16be(buf, &wo, 1); put16be(buf, &wo, 0);
    memset(buf + wo, ' ', 16); memcpy(buf + wo, "WIDEPC", 6); wo += 16;
    memset(buf + wo, ' ', 16); memcpy(buf + wo, "LEMURSCU", 8); wo += 16;
    memset(buf + wo, 0, 32); wo += 32;
    dicom_put_uid_item(buf, &wo, 0x10, "1.2.840.10008.3.1.1.1");
    dicom_put_wide_presentation_context(buf, &wo, 5);
    body_len = (uint32_t)(wo - wstart); buf[wlen_pos]=(uint8_t)(body_len>>24); buf[wlen_pos+1]=(uint8_t)(body_len>>16); buf[wlen_pos+2]=(uint8_t)(body_len>>8); buf[wlen_pos+3]=(uint8_t)body_len;
    check_dicom_metamorphic(buf, wo, "DICOM wide presentation context", 0);
    size_t o2 = 0; buf[o2++] = DICOM_PDU_P_DATA_TF; buf[o2++] = 0; size_t len_pos = o2; put32be(buf, &o2, 0);
    for (int i = 0; i < DICOM_MAX_PDV_ITEMS + 1; i++) { put32be(buf, &o2, 3); buf[o2++] = 1; buf[o2++] = DICOM_PDV_FLAG_LAST_FRAGMENT; buf[o2++] = (uint8_t)i; }
    uint32_t pdulen = (uint32_t)(o2 - (len_pos + 4)); buf[len_pos]=(uint8_t)(pdulen>>24); buf[len_pos+1]=(uint8_t)(pdulen>>16); buf[len_pos+2]=(uint8_t)(pdulen>>8); buf[len_pos+3]=(uint8_t)pdulen;
    check_dicom_metamorphic(buf, o2, "DICOM over max PDVs", 0);
    uint8_t bad_types[] = {DICOM_PDU_A_ASSOCIATE_RQ,DICOM_PDU_A_ASSOCIATE_AC,DICOM_PDU_A_ASSOCIATE_RJ,DICOM_PDU_P_DATA_TF,DICOM_PDU_A_RELEASE_RQ,DICOM_PDU_A_RELEASE_RP,DICOM_PDU_A_ABORT};
    for (size_t bi=0; bi<sizeof(bad_types); bi++) { buf[0]=bad_types[bi]; buf[1]=0; put32be(buf, &(size_t){2}, 0); (void)parse_dicom_msg(buf, 6, dicom_rt1, 4); }

    size_t ov = 0;
    buf[ov++] = DICOM_PDU_P_DATA_TF; buf[ov++] = 0; put32be(buf, &ov, (uint32_t)(4 + 2 + DICOM_MAX_PDV_DATA_LEN));
    put32be(buf, &ov, (uint32_t)(2 + DICOM_MAX_PDV_DATA_LEN)); buf[ov++] = 1; buf[ov++] = DICOM_PDV_FLAG_COMMAND;
    for (uint32_t z = 0; z < DICOM_MAX_PDV_DATA_LEN; z++) buf[ov++] = 0;
    buf[ov++] = DICOM_PDU_P_DATA_TF; buf[ov++] = 0; put32be(buf, &ov, 7);
    put32be(buf, &ov, 3); buf[ov++] = 1; buf[ov++] = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT; buf[ov++] = 0;
    CHECK(parse_dicom_msg(buf, (u32)ov, dicom_rt1, 16) == 2, "DICOM oversized command fragment safety parse");

    dicom_packet_t pkt; u32 out_len;
    memset(&pkt, 0, sizeof(pkt)); pkt.type = DICOM_PKT_UNKNOWN; pkt.raw_length = 9; memcpy(pkt.raw_data, "\x99\0\0\0\0\3abc", 9);
    out_len = sizeof(out); CHECK(reassemble_dicom_msgs(&pkt, 1, out, &out_len) == 0, "DICOM direct unknown reassemble");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = DICOM_PKT_A_ASSOCIATE_RQ; pkt.u.a_associate_rq.protocol_version = 1; pkt.u.a_associate_rq.application_context.item_type = 0x10; pkt.u.a_associate_rq.application_context.application_context_name.length = 21; memcpy(pkt.u.a_associate_rq.application_context.application_context_name.value, "1.2.840.10008.3.1.1.1", 21); pkt.u.a_associate_rq.has_user_info = 1; pkt.u.a_associate_rq.user_info.item_type = 0x50; pkt.u.a_associate_rq.user_info.has_user_data = 0; pkt.u.a_associate_rq.user_info.user_data_length = 0;
    out_len = sizeof(out); CHECK(reassemble_dicom_msgs(&pkt, 1, out, &out_len) == 0, "DICOM empty user info reassemble");
    /* Exercise generated (not parsed) PS3.7 request command bodies. */
    const uint16_t no_dataset_cmds[] = {
        DICOM_DIMSE_C_ECHO_RQ, DICOM_DIMSE_C_CANCEL_RQ,
        DICOM_DIMSE_N_GET_RQ, DICOM_DIMSE_N_DELETE_RQ
    };
    for (size_t ci=0; ci<sizeof(no_dataset_cmds)/sizeof(no_dataset_cmds[0]); ci++) {
        memset(&pkt, 0, sizeof(pkt));
        pkt.type = DICOM_PKT_P_DATA_TF;
        pkt.u.p_data_tf.pdv_count = 1;
        dicom_pdv_item_t *pdv = &pkt.u.p_data_tf.pdvs[0];
        pdv->presentation_context_id = 1;
        pdv->control_header = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
        pdv->has_dimse_command = 1;
        pdv->dimse_command_field = no_dataset_cmds[ci];
        pdv->dimse_message_id = 1;
        pdv->dimse_message_id_responded_to = 1;
        out_len = sizeof(out);
        CHECK(reassemble_dicom_msgs(&pkt, 1, out, &out_len) == 0,
              "DICOM generated no-dataset command reassembles");
        CHECK(parse_dicom_msg(out, out_len, dicom_rt1, 1) == 1,
              "DICOM generated no-dataset command reparses");
    }
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = DICOM_PKT_P_DATA_TF;
    pkt.u.p_data_tf.pdv_count = 1;
    pkt.u.p_data_tf.pdvs[0].has_dimse_command = 1;
    pkt.u.p_data_tf.pdvs[0].control_header = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
    pkt.u.p_data_tf.pdvs[0].presentation_context_id = 1;
    pkt.u.p_data_tf.pdvs[0].dimse_command_field = DICOM_DIMSE_C_ECHO_RQ;
    pkt.u.p_data_tf.pdvs[0].dimse_status = 0x1234;
    out_len = sizeof(out);
    CHECK(reassemble_dicom_msgs(&pkt, 1, out, &out_len) == 0,
          "DICOM generated status serialization branch");
    memset(&pkt, 0, sizeof(pkt)); pkt.type = (dicom_packet_type_t)255; out_len = sizeof(out); CHECK(reassemble_dicom_msgs(&pkt, 1, out, &out_len) != 0, "DICOM invalid packet type rejected");
}

int main(void) {
    sanity_dns();
    sanity_ssh();
    sanity_tls();
    sanity_dicom();
    exercise_dns_coverage_edges();
    exercise_ssh_coverage_edges();
    exercise_tls_coverage_edges();
    exercise_dicom_coverage_edges();
    if (failures) {
        fprintf(stderr, "rfc_format_sanity: %d failures\n", failures);
        return 1;
    }
    puts("rfc_format_sanity: OK");
    return 0;
}
