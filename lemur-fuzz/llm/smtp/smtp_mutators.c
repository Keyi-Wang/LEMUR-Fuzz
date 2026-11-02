/* smtp mutators source file */
#include "smtp.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>


static void set_cstr(char dst[], size_t cap, const char *s){
    if (!dst || cap == 0) return;
    if (!s) s = "";
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, s, n);
    dst[n] = '\0';
}

static size_t emit_run(char *dst, size_t cap, char ch, size_t len){
    if (!dst || cap == 0) return 0;
    size_t n = len < (cap-1) ? len : (cap-1);
    memset(dst, (unsigned char)ch, n);
    dst[n] = '\0';
    return n;
}

static void toggle_case(char *s){
    if (!s) return;
    for (; *s; ++s){
        unsigned char c = (unsigned char)*s;
        if (c >= 'a' && c <= 'z') *s = (char)toupper(c);
        else if (c >= 'A' && c <= 'Z') *s = (char)tolower(c);
    }
}

static void build_multilabel(char *dst, size_t cap,
                             size_t labels, size_t label_len, char base_ch){
    if (!dst || cap == 0){ return; }
    size_t pos = 0;
    for (size_t i = 0; i < labels; ++i){
        char ch = (char)(base_ch + (i % 10));
        for (size_t j = 0; j < label_len && pos + 1 < cap; ++j){
            dst[pos++] = ch;
        }
        if (i + 1 < labels && pos + 1 < cap){
            dst[pos++] = '.';
        }
    }
    dst[pos < cap ? pos : cap-1] = '\0';
}

int mutate_helo_domain(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };   /* A-H semantic dimensions */
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELO) continue;

        smtp_helo_packet_t *h = &pkts[i].pkt.helo;

        if (h->command[0] == '\0') set_cstr(h->command, sizeof h->command, "HELO");
        if (h->space[0] == '\0')   set_cstr(h->space,   sizeof h->space,   " ");

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(h->domain, sizeof h->domain, "localhost"); break;
            case 1:  set_cstr(h->domain, sizeof h->domain, "example.com"); break;
            case 2:  set_cstr(h->domain, sizeof h->domain, "mail.example.org"); break;

            /* ===== B. Boundary values ===== */
            case 3:  set_cstr(h->domain, sizeof h->domain, ""); break;            /* empty (min) */
            case 4:  set_cstr(h->domain, sizeof h->domain, "x"); break;           /* single char */
            case 5:  set_cstr(h->domain, sizeof h->domain, "a..b"); break;       /* empty interior label */
            case 6: { /* at-capacity fill */
                size_t cap = sizeof h->domain;
                if (cap > 1){ memset(h->domain, 'D', cap-1); h->domain[cap-1] = '\0'; }
                else h->domain[0] = '\0';
                break;
            }

            /* ===== C. Equivalence-class alternatives ===== */
            case 7:  set_cstr(h->domain, sizeof h->domain, "example.com."); break;       /* FQDN trailing dot */
            case 8:  set_cstr(h->domain, sizeof h->domain, "127.0.0.1"); break;           /* bare IPv4 */
            case 9:  set_cstr(h->domain, sizeof h->domain, "[127.0.0.1]"); break;         /* IPv4 literal */
            case 10: set_cstr(h->domain, sizeof h->domain, "[::1]"); break;               /* IPv6 literal */
            case 11: set_cstr(h->domain, sizeof h->domain, "[IPv6:2001:db8::1]"); break;  /* IPv6 tagged */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* domain is free-form string; "range" = per-label length envelope (<=63 octets). */
            case 12: { /* label of exactly 63 octets (max legal label) */
                char tmp[SMTP_SZ_DOMAIN];
                size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'a', 63);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                const char *com = "com";
                size_t l = strlen(com);
                if (pos + l < sizeof(tmp)){ memcpy(tmp+pos, com, l); pos += l; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 13: { /* label of 64 octets (one past max legal label) */
                char tmp[SMTP_SZ_DOMAIN];
                size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'b', 64);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                if (pos+3 < sizeof(tmp)) { tmp[pos++]='c'; tmp[pos++]='o'; tmp[pos++]='m'; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }

            /* ===== E. Encoding-validity preservation ===== */
            case 14: set_cstr(h->domain, sizeof h->domain, "xn--bcher-kva.de"); break; /* valid IDNA/punycode */
            case 15: set_cstr(h->domain, sizeof h->domain, "bücher.de"); break;         /* valid UTF-8 (SMTPUTF8) */
            case 16: set_cstr(h->domain, sizeof h->domain, "[IPv6:GGGG::1]"); break;    /* well-formed brackets, bad hex group */

            /* ===== F. Padding / alignment ===== */
            case 17: { /* multilabel padding to a fixed structural length */
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 6, 3, 'a'); /* aaa.bbb.ccc... */
                break;
            }
            case 18: { /* long padded structure (4 labels x 30) */
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 4, 30, 'x');
                break;
            }

            /* ===== G. Prefix / suffix variants ===== */
            case 19: set_cstr(h->domain, sizeof h->domain, "-bad.tld"); break;            /* bad leading char */
            case 20: set_cstr(h->domain, sizeof h->domain, "my host"); break;             /* embedded whitespace */
            case 21: set_cstr(h->domain, sizeof h->domain, "host\r\nMAIL FROM:<>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 22: set_cstr(h->domain, sizeof h->domain, "host.example.net"); break;
            case 23: set_cstr(h->domain, sizeof h->domain, "sub.domain.example.com"); break;
            default: break;
        }

        if (op % 5 == 0 && h->domain[0]) toggle_case(h->domain);

        mutated++;
    }

    return (int)mutated;
}


int mutate_ehlo_domain(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };   /* A-H semantic dimensions */
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_EHLO) continue;

        smtp_ehlo_packet_t *h = &pkts[i].pkt.ehlo;

        if (h->command[0] == '\0') set_cstr(h->command, sizeof h->command, "EHLO");
        if (h->space[0]   == '\0') set_cstr(h->space,   sizeof h->space,   " ");

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(h->domain, sizeof h->domain, "localhost"); break;
            case 1:  set_cstr(h->domain, sizeof h->domain, "example.com"); break;
            case 2:  set_cstr(h->domain, sizeof h->domain, "mail.example.org"); break;

            /* ===== B. Boundary values ===== */
            case 3:  set_cstr(h->domain, sizeof h->domain, ""); break;            /* empty (min) */
            case 4:  set_cstr(h->domain, sizeof h->domain, "x"); break;           /* single char */
            case 5:  set_cstr(h->domain, sizeof h->domain, "a..b"); break;       /* empty interior label */
            case 6: { /* at-capacity fill */
                size_t cap = sizeof h->domain;
                if (cap > 1){ memset(h->domain, 'D', cap-1); h->domain[cap-1] = '\0'; }
                else h->domain[0] = '\0';
                break;
            }

            /* ===== C. Equivalence-class alternatives ===== */
            case 7:  set_cstr(h->domain, sizeof h->domain, "example.com."); break;       /* FQDN trailing dot */
            case 8:  set_cstr(h->domain, sizeof h->domain, "127.0.0.1"); break;           /* bare IPv4 */
            case 9:  set_cstr(h->domain, sizeof h->domain, "[127.0.0.1]"); break;         /* IPv4 literal */
            case 10: set_cstr(h->domain, sizeof h->domain, "[::1]"); break;               /* IPv6 literal */
            case 11: set_cstr(h->domain, sizeof h->domain, "[IPv6:2001:db8::1]"); break;  /* IPv6 tagged */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* domain is free-form string; "range" = per-label length envelope (<=63 octets). */
            case 12: { /* label of exactly 63 octets (max legal label) */
                char tmp[SMTP_SZ_DOMAIN]; size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'a', 63);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                const char *com = "com";
                size_t l = strlen(com);
                if (pos + l < sizeof(tmp)){ memcpy(tmp+pos, com, l); pos += l; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }
            case 13: { /* label of 64 octets (one past max legal label) */
                char tmp[SMTP_SZ_DOMAIN]; size_t pos = 0;
                pos += emit_run(tmp+pos, sizeof(tmp)-pos, 'b', 64);
                if (pos+1 < sizeof(tmp)) tmp[pos++]='.';
                if (pos+3 < sizeof(tmp)){ tmp[pos++]='c'; tmp[pos++]='o'; tmp[pos++]='m'; }
                tmp[pos < sizeof(tmp) ? pos : sizeof(tmp)-1] = '\0';
                set_cstr(h->domain, sizeof h->domain, tmp);
                break;
            }

            /* ===== E. Encoding-validity preservation ===== */
            case 14: set_cstr(h->domain, sizeof h->domain, "xn--bcher-kva.de"); break; /* valid IDNA/punycode */
            case 15: set_cstr(h->domain, sizeof h->domain, "bücher.de"); break;         /* valid UTF-8 (SMTPUTF8) */
            case 16: set_cstr(h->domain, sizeof h->domain, "[IPv6:GGGG::1]"); break;    /* well-formed brackets, bad hex group */

            /* ===== F. Padding / alignment ===== */
            case 17: { /* multilabel padding to a fixed structural length */
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 6, 3, 'a'); /* aaa.bbb.ccc... */
                break;
            }
            case 18: { /* long padded structure (4 labels x 30) */
                set_cstr(h->domain, sizeof h->domain, "");
                build_multilabel(h->domain, sizeof h->domain, 4, 30, 'x');
                break;
            }

            /* ===== G. Prefix / suffix variants ===== */
            case 19: set_cstr(h->domain, sizeof h->domain, "-bad.tld"); break;            /* bad leading char */
            case 20: set_cstr(h->domain, sizeof h->domain, "my host"); break;             /* embedded whitespace */
            case 21: set_cstr(h->domain, sizeof h->domain, "host\r\nMAIL FROM:<>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 22: set_cstr(h->domain, sizeof h->domain, "host.example.net"); break;
            case 23: set_cstr(h->domain, sizeof h->domain, "sub.domain.example.com"); break;
            default: break;
        }

        if (op % 5 == 0 && h->domain[0]) toggle_case(h->domain);

        mutated++;
    }

    return (int)mutated;
}


static void build_long_domain(char *out, size_t cap){
    if (!out || cap == 0) return;
    const char *tail = "com";
    size_t pos = 0;
    while (pos + 63 + 1 + strlen(tail) + 1 < cap) {
        memset(out + pos, 'a', 63); pos += 63;
        out[pos++] = '.';
    }
    if (pos + 3 < cap) { memcpy(out+pos, tail, 3); pos += 3; }
    out[pos < cap ? pos : cap-1] = '\0';
}

static void build_long_local(char *out, size_t cap){
    if (!out || cap == 0) return;
    size_t n = (cap-1 > 64 ? 64 : cap-1);
    memset(out, 'L', n ? n-1 : 0);
    if (n) out[n-1] = 'x';
    out[n] = '\0';
}


static void ensure_mail_prefix(smtp_mail_packet_t *m){
    if (!m) return;
    if (m->command[0] == '\0') set_cstr(m->command, sizeof m->command, "MAIL");
    if (m->space1[0]  == '\0') set_cstr(m->space1,  sizeof m->space1,  " ");
    if (m->from_keyword[0] == '\0') set_cstr(m->from_keyword, sizeof m->from_keyword, "FROM:");
}

int mutate_mail_reverse_path(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };   /* A-H semantic dimensions */
    unsigned mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;

        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<>"); break;                          /* null reverse path */
            case 1:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@example.com>"); break;
            case 2:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user.name+tag@example.com>"); break;
            case 3:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<postmaster>"); break;

            /* ===== B. Boundary values ===== */
            case 4:  set_cstr(m->reverse_path, sizeof m->reverse_path, ""); break;                            /* empty (min) */
            case 5:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<>"); break;                           /* minimal non-empty */
            case 6: { /* at-capacity fill between angle brackets */
                size_t cap = sizeof m->reverse_path;
                if (cap <= 2) { set_cstr(m->reverse_path, cap, ""); break; }
                m->reverse_path[0] = '<';
                memset(m->reverse_path+1, 'A', cap-3);
                m->reverse_path[cap-2] = '>';
                m->reverse_path[cap-1] = '\0';
            } break;

            /* ===== C. Equivalence-class alternatives ===== */
            case 7:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[127.0.0.1]>"); break;           /* IPv4 literal host */
            case 8:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[IPv6:2001:db8::1]>"); break;    /* IPv6 literal host */
            case 9:  set_cstr(m->reverse_path, sizeof m->reverse_path, "<@a.example,@b.example:user@c.example>"); break; /* source route */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* reverse_path is an addr-spec; "range" = local-part length envelope (<=64). */
            case 10: { /* long-but-legal local part + long domain */
                char local[128]; build_long_local(local, sizeof local);
                char dom[256];   build_long_domain(dom, sizeof dom);
                char tmp[SMTP_SZ_PATH];
                snprintf(tmp, sizeof tmp, "<%s@%s>", local, dom);
                set_cstr(m->reverse_path, sizeof m->reverse_path, tmp);
            } break;

            /* ===== E. Encoding-validity preservation ===== */
            case 11: set_cstr(m->reverse_path, sizeof m->reverse_path, "<\"weird name\"@example.com>"); break;          /* quoted local-part */
            case 12: set_cstr(m->reverse_path, sizeof m->reverse_path, "<xn--fsqu00a@xn--0zwm56d.xn--0zwm56d>"); break;  /* punycode */
            case 13: set_cstr(m->reverse_path, sizeof m->reverse_path, "<用户@例子.测试>"); break;                          /* SMTPUTF8 */

            /* ===== F. Padding / alignment ===== */
            case 14: set_cstr(m->reverse_path, sizeof m->reverse_path,
                              "<\"very.(),:;<>[]\\\".VERY.\\\"very@\\ \\\"very\\\".unusual\"@strange.example.com>"); break; /* padded quoted form */

            /* ===== G. Prefix / suffix variants ===== */
            case 15: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@example.com"); break;          /* missing closing > */
            case 16: set_cstr(m->reverse_path, sizeof m->reverse_path, "user@example.com>"); break;          /* missing leading < */
            case 17: set_cstr(m->reverse_path, sizeof m->reverse_path, "user@example.com"); break;           /* no angle brackets */
            case 18: set_cstr(m->reverse_path, sizeof m->reverse_path, "<userexample.com>"); break;          /* no @ */
            case 19: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@\r\nRCPT TO:evil@example.com>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 20: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@-bad-.com>"); break;          /* structurally mixed */
            case 21: set_cstr(m->reverse_path, sizeof m->reverse_path, "<u..ser@example.com>"); break;
            case 22: set_cstr(m->reverse_path, sizeof m->reverse_path, "<us er@example.com>"); break;
            case 23: set_cstr(m->reverse_path, sizeof m->reverse_path, "<user@[IPv6:]>"); break;
            default: break;
        }

        mutated++;
    }

    return (int)mutated;
}


static void build_long_envid(char *out, size_t cap){
    if (!out || cap == 0) return;
    size_t n = cap - 1;
    for (size_t i = 0; i < n; ++i) out[i] = (i % 2) ? '9' : 'A';
    out[n] = '\0';
}


int add_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        if (m->optional_args[0] == '\0'){
            set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=12345 BODY=7BIT");
            changed++;
        }
    }
    return changed;
}

int delete_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        if (m->optional_args[0] != '\0'){
            m->optional_args[0] = '\0';
            changed++;
        }
    }
    return changed;
}

int mutate_mail_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };   /* A-H semantic dimensions */
    int mutated = 0;

    char buf[SMTP_SZ_OPTARGS];
    char envid[64];

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_MAIL) continue;
        smtp_mail_packet_t *m = &pkts[i].pkt.mail;
        ensure_mail_prefix(m);
        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=1"); break;
            case 1:  set_cstr(m->optional_args, sizeof m->optional_args, "BODY=7BIT"); break;
            case 2:  set_cstr(m->optional_args, sizeof m->optional_args, "BODY=8BITMIME"); break;
            case 3:  set_cstr(m->optional_args, sizeof m->optional_args, "RET=FULL"); break;
            case 4:  set_cstr(m->optional_args, sizeof m->optional_args, "RET=HDRS"); break;
            case 5:  set_cstr(m->optional_args, sizeof m->optional_args, "SMTPUTF8"); break;
            case 6:  set_cstr(m->optional_args, sizeof m->optional_args, "AUTH=<>"); break;
            case 7:  set_cstr(m->optional_args, sizeof m->optional_args, "MT-PRIORITY=3"); break; /* RFC 6710 */

            /* ===== B. Boundary values ===== */
            case 8:  set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=4294967295"); break;  /* max u32 */
            case 9:  set_cstr(m->optional_args, sizeof m->optional_args, ""); break;                 /* empty (min) */
            case 10: { /* at-capacity fill */
                size_t cap = sizeof m->optional_args;
                if (cap) {
                    memset(m->optional_args, 'A', cap-1);
                    m->optional_args[cap-1] = '\0';
                }
            } break;

            /* ===== C. Equivalence-class alternatives ===== */
            case 11: set_cstr(m->optional_args, sizeof m->optional_args, "AUTH=ZGVtbw=="); break;                       /* base64 'demo' */
            case 12: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=123 BODY=8BITMIME SMTPUTF8"); break;       /* multi-arg combo */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* BODY enum: {7BIT, 8BIT, 8BITMIME}; RET enum: {FULL, HDRS}. */
            case 13: set_cstr(m->optional_args, sizeof m->optional_args, "ENVID=abc-123_./"); break;  /* ENVID value range */

            /* ===== E. Encoding-validity preservation ===== */
            case 14: {
                build_long_envid(envid, sizeof envid);
                snprintf(buf, sizeof buf, "ENVID=%s", envid);
                set_cstr(m->optional_args, sizeof m->optional_args, buf);
                break;
            }

            /* ===== F. Padding / alignment ===== */
            /* n/a for kwarg list — optional_args is whitespace-delimited, not fixed-width padded. */

            /* ===== G. Prefix / suffix variants ===== */
            case 15: set_cstr(m->optional_args, sizeof m->optional_args, " SIZE=1   BODY=8BITMIME  "); break;  /* leading/trailing WS */
            case 16: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=1\r\nRCPT TO:<evil@example.com>"); break; /* CRLF suffix inject */
            case 17: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE"); break;                        /* missing '=' */

            /* ===== H. Random valid mix ===== */
            case 18: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=-1"); break;                    /* structurally valid, semantically odd */
            case 19: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=0x100"); break;
            case 20: set_cstr(m->optional_args, sizeof m->optional_args, "BODY=9BIT"); break;                  /* out-of-enum BODY */
            case 21: set_cstr(m->optional_args, sizeof m->optional_args, "AUTH="); break;                       /* empty value */
            case 22: set_cstr(m->optional_args, sizeof m->optional_args, "FROB=1"); break;                     /* unknown kwarg */
            case 23: set_cstr(m->optional_args, sizeof m->optional_args, "SIZE=1 SIZE=2"); break;              /* duplicate kwarg */
            default: break;
        }

        mutated++;
    }

    return mutated;
}


static void ensure_rcpt_prefix(smtp_rcpt_packet_t *r){
    if (!r) return;
    if (!r->command[0])   set_cstr(r->command,   sizeof r->command,   "RCPT");
    if (!r->space1[0])    set_cstr(r->space1,    sizeof r->space1,    " ");
    if (!r->to_keyword[0])set_cstr(r->to_keyword,sizeof r->to_keyword,"TO:");
}

static void cat_s(char *dst, size_t cap, const char *s){
    if (!dst || !cap || !s) return;
    size_t cur = strlen(dst);
    if (cur >= cap) { dst[cap-1] = '\0'; return; }
    size_t rem = cap - 1 - cur;
    size_t n = strlen(s);
    if (n > rem) n = rem;
    if (n) memcpy(dst + cur, s, n);
    dst[cur + n] = '\0';
}

static void cat_repeat(char *dst, size_t cap, char ch, size_t n){
    if (!dst || !cap || n == 0) return;
    size_t cur = strlen(dst);
    if (cur >= cap) { dst[cap-1] = '\0'; return; }
    size_t rem = cap - 1 - cur;
    if (n > rem) n = rem;
    memset(dst + cur, (unsigned char)ch, n);
    dst[cur + n] = '\0';
}

static void build_route_addr(char *out, size_t cap){
    if (!out || cap == 0) return;
    out[0] = '\0';
    cat_s(out, cap, "<");
    for (int i = 0; i < 16; ++i){
        char hop[64];
        snprintf(hop, sizeof hop, "@r%d.example,", i);
        size_t before = strlen(out);
        cat_s(out, cap, hop);
        if (strlen(out) == before) break;
    }
    cat_s(out, cap, "user@example.com>");
}

int mutate_rcpt_forward_path(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };   /* A-H semantic dimensions */
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<alice@example.com>"); break;
            case 1:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user+tag@example.com>"); break;
            case 2:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<postmaster@example.com>"); break;

            /* ===== B. Boundary values ===== */
            case 3:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<>"); break;                 /* null forward path (min) */
            case 4:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<a@b.c>"); break;            /* minimal addr-spec */
            case 5: { /* at-capacity fill between angle brackets */
                char tmp[SMTP_SZ_PATH]; tmp[0] = '\0';
                cat_s(tmp, sizeof tmp, "<");
                cat_repeat(tmp, sizeof tmp, 'A', 256);
                cat_s(tmp, sizeof tmp, "@example.com>");
                set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
            } break;

            /* ===== C. Equivalence-class alternatives ===== */
            case 6:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[192.0.2.1]>"); break;               /* IPv4 literal */
            case 7:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[IPv6:2001:db8::1]>"); break;        /* IPv6 literal */
            case 8:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<@a.example,@b.example:user@example.net>"); break; /* source route */
            case 9:  set_cstr(r->forward_path, SMTP_SZ_PATH, "<host!user>"); break;                      /* bang path */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* addr-spec; "range" = label-count / length envelope. */
            case 10: { /* many-label domain (within label-count envelope) */
                char tmp[SMTP_SZ_PATH]; tmp[0] = '\0';
                cat_s(tmp, sizeof tmp, "<u@");
                for (int j = 0; j < 20; ++j){
                    char lab[16]; snprintf(lab, sizeof lab, "d%d.", j);
                    size_t before = strlen(tmp);
                    cat_s(tmp, sizeof tmp, lab);
                    if (strlen(tmp) == before) break;
                }
                cat_s(tmp, sizeof tmp, "example>");
                set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
            } break;

            /* ===== E. Encoding-validity preservation ===== */
            case 11: set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"weird name\"@example.com>"); break;     /* quoted local-part */
            case 12: set_cstr(r->forward_path, SMTP_SZ_PATH, "<\"a\\\"b\"@example.com>"); break;          /* escaped quote in quoted string */
            case 13: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@xn--exmple-cua.com>"); break;        /* IDNA/punycode */
            case 14: set_cstr(r->forward_path, SMTP_SZ_PATH, "<δοκιμή@παράδειγμα.δοκιμή>"); break;       /* SMTPUTF8 */

            /* ===== F. Padding / alignment ===== */
            case 15: { /* padded multi-hop source route */
                char tmp[SMTP_SZ_PATH]; build_route_addr(tmp, sizeof tmp);
                set_cstr(r->forward_path, SMTP_SZ_PATH, tmp);
            } break;

            /* ===== G. Prefix / suffix variants ===== */
            case 16: set_cstr(r->forward_path, SMTP_SZ_PATH, "user@example.com"); break;          /* missing angle brackets */
            case 17: set_cstr(r->forward_path, SMTP_SZ_PATH, "<userexample.com>"); break;         /* missing @ */
            case 18: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@example.com.>"); break;       /* trailing dot suffix */
            case 19: set_cstr(r->forward_path, SMTP_SZ_PATH, "<victim@example.com\r\nDATA>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 20: set_cstr(r->forward_path, SMTP_SZ_PATH, "<.user.@example..com>"); break;     /* mixed boundary chars */
            case 21: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user @example.com>"); break;       /* embedded whitespace */
            case 22: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@-bad-.com>"); break;
            case 23: set_cstr(r->forward_path, SMTP_SZ_PATH, "<user@[IPv6:fe80::1%25eth0]>"); break; /* IPv6 zone id */
            default: break;
        }

        mutated++;
    }

    return mutated;
}


int add_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int added = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);
        if (!r->optional_args[0]){
            set_cstr(r->optional_args, sizeof r->optional_args,
                     "NOTIFY=SUCCESS,DELAY,FAILURE ORCPT=rfc822;user@example.com");
            added++;
        }
    }
    return added;
}


int delete_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int removed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        if (r->optional_args[0]){
            r->optional_args[0] = '\0';
            removed++;
        }
    }
    return removed;
}


int mutate_rcpt_optional_args(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 26 };   /* A-H semantic dimensions */
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_RCPT) continue;
        smtp_rcpt_packet_t *r = &pkts[i].pkt.rcpt;
        ensure_rcpt_prefix(r);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=SUCCESS,DELAY,FAILURE"); break;
            case 1:  set_cstr(r->optional_args, sizeof r->optional_args, "notify=never"); break;
            case 2:  set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=rfc822;Bob@example.com"); break;
            case 3:  set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=SUCCESS ORCPT=rfc822;user@example.com"); break;

            /* ===== B. Boundary values ===== */
            case 4:  set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY="); break;     /* empty value (min) */
            case 5:  set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY"); break;      /* missing '=' */

            /* ===== C. Equivalence-class alternatives ===== */
            case 6:  set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=utf-8;δοκιμή@παράδειγμα.δοκιμή"); break; /* UTF-8 ORCPT addr-type */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* NOTIFY enum: {NEVER, SUCCESS, FAILURE, DELAY}; ORCPT addr-type registry. */
            case 7:  set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=badtype;user@example.com"); break;  /* out-of-registry addr-type */
            case 8:  set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=success,unknown"); break;          /* out-of-enum NOTIFY member */

            /* ===== E. Encoding-validity preservation ===== */
            case 9:  set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=\"rfc822;user@example.com\""); break;  /* quoted ORCPT value */
            case 10: set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=\tsuccess,delay"); break;             /* tab-separated (WS-preserving) */

            /* ===== F. Padding / alignment ===== */
            case 11: { /* padded long ORCPT value */
                char tmp[SMTP_SZ_OPTARGS]; tmp[0]='\0';
                cat_s(tmp, sizeof tmp, "ORCPT=rfc822;");
                cat_repeat(tmp, sizeof tmp, 'A', 400);
                cat_s(tmp, sizeof tmp, "@example.com");
                set_cstr(r->optional_args, sizeof r->optional_args, tmp);
            } break;
            case 12: { /* padded repeated NOTIFY list */
                char tmp[SMTP_SZ_OPTARGS]; tmp[0]='\0';
                cat_s(tmp, sizeof tmp, "NOTIFY=");
                for (int j = 0; j < 50; ++j){
                    cat_s(tmp, sizeof tmp, "success,");
                }
                set_cstr(r->optional_args, sizeof r->optional_args, tmp);
            } break;

            /* ===== G. Prefix / suffix variants ===== */
            case 13: set_cstr(r->optional_args, sizeof r->optional_args, "NoTiFy = success , failure"); break;  /* mixed case + spacing */
            case 14: set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY =\tNEVER"); break;
            case 15: set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY==NEVER"); break;               /* double '=' */
            case 16: set_cstr(r->optional_args, sizeof r->optional_args, "=NEVER"); break;                      /* bare value */
            case 17: set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=success\r\nDATA"); break;       /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 18: set_cstr(r->optional_args, sizeof r->optional_args, "FOO=bar"); break;                     /* unknown kwarg */
            case 19: set_cstr(r->optional_args, sizeof r->optional_args, "X-LONGKEY="); break;                   /* unknown long-key kwarg */
            case 20: set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=SUCCESS NOTIFY=NEVER"); break;  /* duplicate NOTIFY */
            case 21: set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=rfc822;u@example.com ORCPT=rfc822;v@example.net"); break; /* duplicate ORCPT */
            case 22: set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=rfc822 user@example.com"); break; /* missing ';' */
            case 23: set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=rfc822;user@\x01example.com"); break; /* control byte in value */
            case 24: set_cstr(r->optional_args, sizeof r->optional_args, "ORCPT=rfc822;u@example.com   NOTIFY=SUCCESS,FAILURE"); break;
            case 25: set_cstr(r->optional_args, sizeof r->optional_args, "NOTIFY=,," ); break;                    /* empty list members */
            default: break;
        }

        mutated++;
    }

    return mutated;
}


static void ensure_vrfy_prefix(smtp_vrfy_packet_t *v){
    if (!v) return;
    if (!v->command[0]) set_cstr(v->command, sizeof v->command, "VRFY");
    if (!v->crlf[0])    set_cstr(v->crlf,    sizeof v->crlf,    "\r\n");
    if (!v->space[0]) set_cstr(v->space, sizeof v->space, " ");
}

int mutate_vrfy_string(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };

    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_VRFY) continue;
        smtp_vrfy_packet_t *v = &pkts[i].pkt.vrfy;

        ensure_vrfy_prefix(v);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(v->string, sizeof v->string, "user@example.com"); break;
            case 1:  set_cstr(v->string, sizeof v->string, "postmaster"); break;
            case 2:  set_cstr(v->string, sizeof v->string, "Full Name <user@example.com>"); break;
            case 3:  set_cstr(v->string, sizeof v->string, "\"weird name\"@example.com"); break;

            /* ===== B. Boundary values ===== */
            case 4:  set_cstr(v->string, sizeof v->string, ""); break;            /* empty (min) */
            case 5:  set_cstr(v->string, sizeof v->string, "\t  "); break;        /* whitespace-only */
            case 6: { /* at-capacity local-part fill */
                char tmp[SMTP_SZ_VRFY_STR]; tmp[0] = '\0';
                cat_repeat(tmp, sizeof tmp, 'A', 450);
                cat_s(tmp, sizeof tmp, "@example.com");
                set_cstr(v->string, sizeof v->string, tmp);
            } break;

            /* ===== C. Equivalence-class alternatives ===== */
            case 7:  set_cstr(v->string, sizeof v->string, "user@[192.0.2.1]"); break;                 /* IPv4 literal */
            case 8:  set_cstr(v->string, sizeof v->string, "user@[IPv6:2001:db8::1]"); break;          /* IPv6 literal */
            case 9:  set_cstr(v->string, sizeof v->string, "<@a.example,@b.example:user@example.com>"); break; /* source route */
            case 10: set_cstr(v->string, sizeof v->string, "user%example.com@relay.local"); break;     /* percent-hack */
            case 11: set_cstr(v->string, sizeof v->string, "host1!host2!user"); break;                  /* bang path */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* vrfy string is a user/addr token; "range" = token-length envelope. */

            /* ===== E. Encoding-validity preservation ===== */
            case 12: set_cstr(v->string, sizeof v->string, "用户@例子.公司"); break;             /* SMTPUTF8/IDN */
            case 13: set_cstr(v->string, sizeof v->string, "xn--fsqu00a@xn--0zwm56d"); break;     /* punycode */
            case 14: set_cstr(v->string, sizeof v->string, "\"us\\er\"@exa\\mple.com"); break;    /* escaped chars in quoted strings */

            /* ===== F. Padding / alignment ===== */
            case 15: set_cstr(v->string, sizeof v->string, "User (comment) <user@example.com>"); break;  /* padded with comment phrase */
            case 16: set_cstr(v->string, sizeof v->string, "  user.name+tag  @  example.com  "); break;   /* WS-padded */

            /* ===== G. Prefix / suffix variants ===== */
            case 17: set_cstr(v->string, sizeof v->string, ".user@example.com"); break;        /* leading dot */
            case 18: set_cstr(v->string, sizeof v->string, "user@example.com."); break;          /* trailing dot suffix */
            case 19: set_cstr(v->string, sizeof v->string, "\"user@example.com"); break;        /* unclosed quote prefix */
            case 20: set_cstr(v->string, sizeof v->string, "user@example.com\r\nRCPT TO:<evil@example.com>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 21: set_cstr(v->string, sizeof v->string, "a..b@example.com"); break;          /* double-dot interior */
            case 22: set_cstr(v->string, sizeof v->string, "userexample.com"); break;            /* no @ */
            case 23: set_cstr(v->string, sizeof v->string, "user@exa\x01mple.com"); break;       /* embedded control byte */
            default: break;
        }

        mutated++;
    }

    return mutated;
}


static void ensure_expn_prefix(smtp_expn_packet_t *e){
    if (!e) return;
    if (!e->command[0]) set_cstr(e->command, sizeof e->command, "EXPN");
    if (!e->space[0])   set_cstr(e->space,   sizeof e->space,   " ");
    if (!e->crlf[0])    set_cstr(e->crlf,    sizeof e->crlf,    "\r\n");
}

int mutate_expn_mailing_list(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts || n_pkts == 0) return 0;

    static unsigned op_idx = 0;
    enum { OPS = 24 };

    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_EXPN) continue;
        smtp_expn_packet_t *e = &pkts[i].pkt.expn;

        ensure_expn_prefix(e);

        unsigned op = (op_idx++) % OPS;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(e->mailing_list, sizeof e->mailing_list, "staff"); break;
            case 1:  set_cstr(e->mailing_list, sizeof e->mailing_list, "all"); break;
            case 2:  set_cstr(e->mailing_list, sizeof e->mailing_list, "dev-team"); break;
            case 3:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list@example.com"); break;
            case 4:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list+tag@example.com"); break;

            /* ===== B. Boundary values ===== */
            case 5:  set_cstr(e->mailing_list, sizeof e->mailing_list, ""); break;          /* empty (min) */
            case 6:  set_cstr(e->mailing_list, sizeof e->mailing_list, "\t \t"); break;      /* whitespace-only */
            case 7: { /* at-capacity fill */
                char tmp[SMTP_SZ_LISTNAME]; tmp[0] = '\0';
                cat_repeat(tmp, sizeof tmp, 'A', SMTP_SZ_LISTNAME - 10);
                set_cstr(e->mailing_list, sizeof e->mailing_list, tmp);
            } break;

            /* ===== C. Equivalence-class alternatives ===== */
            case 8:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list@[192.0.2.5]"); break;       /* IPv4 literal */
            case 9:  set_cstr(e->mailing_list, sizeof e->mailing_list, "list@[IPv6:2001:db8::25]"); break; /* IPv6 literal */
            case 10: set_cstr(e->mailing_list, sizeof e->mailing_list, "list%example.com@relay.local"); break; /* percent-hack */
            case 11: set_cstr(e->mailing_list, sizeof e->mailing_list, "host1!host2!list"); break;        /* bang path */
            case 12: set_cstr(e->mailing_list, sizeof e->mailing_list, "<@a.example,@b.example:list@example.com>"); break; /* source route */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* mailing_list is a list-name token; "range" = token-length envelope. */

            /* ===== E. Encoding-validity preservation ===== */
            case 13: set_cstr(e->mailing_list, sizeof e->mailing_list, "\"Dev Team\""); break;  /* quoted phrase */
            case 14: set_cstr(e->mailing_list, sizeof e->mailing_list, "开发者列表"); break;     /* SMTPUTF8 */

            /* ===== F. Padding / alignment ===== */
            case 15: set_cstr(e->mailing_list, sizeof e->mailing_list, "  team  "); break;     /* WS-padded */
            case 16: set_cstr(e->mailing_list, sizeof e->mailing_list, "list(comment)"); break; /* comment-padded */

            /* ===== G. Prefix / suffix variants ===== */
            case 17: set_cstr(e->mailing_list, sizeof e->mailing_list, ".list"); break;          /* leading dot */
            case 18: set_cstr(e->mailing_list, sizeof e->mailing_list, "li..st"); break;        /* double-dot interior */
            case 19: set_cstr(e->mailing_list, sizeof e->mailing_list, "\"unclosed"); break;     /* unclosed quote prefix */
            case 20: set_cstr(e->mailing_list, sizeof e->mailing_list, "list\r\nRCPT TO:<evil@example.com>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 21: set_cstr(e->mailing_list, sizeof e->mailing_list, "owner-list"); break;
            case 22: set_cstr(e->mailing_list, sizeof e->mailing_list, "list-request"); break;
            case 23: set_cstr(e->mailing_list, sizeof e->mailing_list, "li\x01st"); break;       /* embedded control byte */
            default: break;
        }

        mutated++;
    }

    return mutated;
}


static void ensure_help_prefix(smtp_help_packet_t *h){
    if (!h) return;
    if (!h->command[0]) set_cstr(h->command, sizeof h->command, "HELP");
    if (!h->crlf[0])    set_cstr(h->crlf,    sizeof h->crlf,    "\r\n");
}

static void sync_space_for_help(smtp_help_packet_t *h, int force_trailing_space_when_empty){
    if (!h) return;
    if (h->argument[0] == '\0') {
        set_cstr(h->space, sizeof h->space, force_trailing_space_when_empty ? " " : "");
    } else {
        set_cstr(h->space, sizeof h->space, " ");
    }
}

int add_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);
        set_cstr(h->argument, sizeof h->argument, "MAIL");
        sync_space_for_help(h, 0);
        changed++;
    }
    return changed;
}

int delete_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);
        set_cstr(h->argument, sizeof h->argument, "");
        sync_space_for_help(h, 0);
        changed++;
    }
    return changed;
}

int mutate_smtp_help_argument(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;

    static unsigned seq = 0;
    enum { OPS = 20 };   /* A-H semantic dimensions */
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_HELP) continue;
        smtp_help_packet_t *h = &pkts[i].pkt.help;
        ensure_help_prefix(h);

        unsigned op = (seq++) % OPS;
        int force_trailing_space_when_empty = 0;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:  set_cstr(h->argument, sizeof h->argument, "MAIL"); break;
            case 1:  set_cstr(h->argument, sizeof h->argument, "RCPT"); break;
            case 2:  set_cstr(h->argument, sizeof h->argument, "DATA"); break;
            case 3:  set_cstr(h->argument, sizeof h->argument, "STARTTLS"); break;
            case 4:  set_cstr(h->argument, sizeof h->argument, "AUTH"); break;

            /* ===== B. Boundary values ===== */
            case 5:  set_cstr(h->argument, sizeof h->argument, ""); break;
            case 6:  set_cstr(h->argument, sizeof h->argument, ""); force_trailing_space_when_empty = 1; break;  /* empty arg + trailing space */
            case 7: { /* at-capacity fill */
                set_cstr(h->argument, sizeof h->argument, "");
                cat_repeat(h->argument, sizeof h->argument, 'A', SMTP_SZ_HELP_ARG - 1);
            } break;

            /* ===== C. Equivalence-class alternatives ===== */
            case 8:  set_cstr(h->argument, sizeof h->argument, "8BITMIME"); break;       /* service extension keyword */
            case 9:  set_cstr(h->argument, sizeof h->argument, "X-UNKNOWN-CMD"); break;  /* unknown command token */

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* argument is a free-form token (command name or extension keyword);
               "enum" = the set of valid SMTP verbs / extension keywords. Covered above in C. */

            /* ===== E. Encoding-validity preservation ===== */
            case 10: set_cstr(h->argument, sizeof h->argument, "帮助"); break;          /* SMTPUTF8 token */

            /* ===== F. Padding / alignment ===== */
            case 11: set_cstr(h->argument, sizeof h->argument, "MAIL   "); break;      /* trailing-WS padding */
            case 12: set_cstr(h->argument, sizeof h->argument, "   MAIL"); break;      /* leading-WS padding */

            /* ===== G. Prefix / suffix variants ===== */
            case 13: set_cstr(h->argument, sizeof h->argument, "--help"); break;        /* CLI-style prefix */
            case 14: set_cstr(h->argument, sizeof h->argument, "MAIL?param=1&x=y"); break; /* query-string suffix */
            case 15: set_cstr(h->argument, sizeof h->argument, "\"MAIL"); break;        /* unclosed quote prefix */
            case 16: set_cstr(h->argument, sizeof h->argument, "MAIL\r\nRCPT TO:<evil@example.com>"); break; /* CRLF suffix injection */

            /* ===== H. Random valid mix ===== */
            case 17: set_cstr(h->argument, sizeof h->argument, "mail"); break;          /* lowercase variant */
            case 18: set_cstr(h->argument, sizeof h->argument, "sTaTuS"); break;        /* mixed-case variant */
            case 19: set_cstr(h->argument, sizeof h->argument, "MA\001IL"); break;     /* embedded control byte */
            default: break;
        }

        sync_space_for_help(h, force_trailing_space_when_empty);

        mutated++;
    }

    return mutated;
}



static void ensure_auth_prefix(smtp_auth_packet_t *a){
    if (!a) return;
    if (!a->command[0])  set_cstr(a->command,  sizeof a->command,  "AUTH");
    if (!a->space1[0])   set_cstr(a->space1,   sizeof a->space1,   " ");
    if (!a->mechanism[0])set_cstr(a->mechanism,sizeof a->mechanism,"PLAIN");
    if (!a->crlf[0])     set_cstr(a->crlf,     sizeof a->crlf,     "\r\n");
}

static void sync_space_for_auth(smtp_auth_packet_t *a, int force_keep_space2_when_empty){
    if (!a) return;
    if (a->initial_response[0] == '\0') {
        set_cstr(a->space2, sizeof a->space2, force_keep_space2_when_empty ? " " : "");
    } else {
        if (a->space2[0] == '\t') {
            return;
        }
        set_cstr(a->space2, sizeof a->space2, " ");
    }
}

int add_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);
        set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
        set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==");
        sync_space_for_auth(a, 0);
        changed++;
    }
    return changed;
}


int delete_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;
    int changed = 0;
    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);
        set_cstr(a->initial_response, sizeof a->initial_response, "");
        sync_space_for_auth(a, 0);
        changed++;
    }
    return changed;
}


int mutate_auth_initial_response(smtp_packet_t *pkts, size_t n_pkts){
    if (!pkts) return 0;

    static unsigned seq = 0;
    enum { OPS = 20 };   /* A-H semantic dimensions */
    int mutated = 0;

    for (size_t i = 0; i < n_pkts; ++i){
        if (pkts[i].cmd_type != SMTP_PKT_AUTH) continue;
        smtp_auth_packet_t *a = &pkts[i].pkt.auth;
        ensure_auth_prefix(a);

        unsigned op = (seq++) % OPS;
        int force_keep_space2_when_empty = 0;

        switch (op){
            /* ===== A. Canonical form ===== */
            case 0:
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw=="); /* \0user\0pass */
                break;
            case 1:
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AGFsaWNlAHNlY3JldA==");
                break;

            /* ===== B. Boundary values ===== */
            case 2:  /* empty initial response (challenge-deferred path) */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "");
                break;
            case 3: { /* at-capacity fill (base64-ish) */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "");
                cat_repeat(a->initial_response, sizeof a->initial_response, 'A',
                           (SMTP_SZ_AUTH_IR/2));
                if ((strlen(a->initial_response) & 3) == 1) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 3);
                else if ((strlen(a->initial_response) & 3) == 2) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 2);
                else if ((strlen(a->initial_response) & 3) == 3) cat_repeat(a->initial_response, sizeof a->initial_response, '=', 1);
                break;
            }

            /* ===== C. Equivalence-class alternatives ===== */
            case 4:
                set_cstr(a->mechanism,        sizeof a->mechanism,        "LOGIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "dXNlcm5hbWU="); /* "username" */
                break;
            case 5:
                set_cstr(a->mechanism,        sizeof a->mechanism,        "CRAM-MD5");
                set_cstr(a->initial_response, sizeof a->initial_response,
                         "dXNlciA5ZTc5Y2RmNTQzN2QxY2QzZjQzY2EwMDAwMDAwMDAwMDAwMDA="); /* "user <hex>" */
                break;
            case 6:
                set_cstr(a->mechanism,        sizeof a->mechanism,        "XOAUTH2");
                set_cstr(a->initial_response, sizeof a->initial_response,
                         "dXNlcj1mb28BYXV0aD1CZWFyZXIgdG9rZW4BAQ==");
                break;

            /* ===== D. Allowed bitfield / enum / range ===== */
            /* SASL mechanism enum: {PLAIN, LOGIN, CRAM-MD5, XOAUTH2, ...}. Covered in C. */
            /* base64 alphabet + padding '=' (0..2 trailing). */

            /* ===== E. Encoding-validity preservation ===== */
            case 7:  /* '+' alone = SASL continuation marker (RFC 4954) */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "+");
                break;
            case 8:  /* invalid UTF-8 byte sequence inside otherwise base64 */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "inv\xC3\x28" "alid==");
                break;
            case 9:  /* non-base64 characters */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "####not_base64####");
                break;

            /* ===== F. Padding / alignment ===== */
            case 10: { /* B-fill to capacity (alignment probe) */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "");
                cat_repeat(a->initial_response, sizeof a->initial_response, 'B',
                           SMTP_SZ_AUTH_IR - 1);
                break;
            }

            /* ===== G. Prefix / suffix variants ===== */
            case 11:  /* leading/trailing whitespace around b64 */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "  AHVzZXIAcGFzcw==  ");
                break;
            case 12:  /* embedded whitespace in b64 */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVz ZXIAcGFz cw==");
                break;
            case 13:  /* trailing lone CR */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==\r");
                break;
            case 14:  /* CRLF suffix injection */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVz\r\nRCPT TO:<x@x>");
                break;

            /* ===== H. Random valid mix ===== */
            case 15:  /* truncated b64 (missing padding) */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw");
                break;
            case 16:  /* excess padding */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw====");
                break;
            case 17:  /* alternate-padding chars */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXI7Y3Bhc3Ms,LS0=");
                break;
            case 18:  /* empty response + kept space2 (alignment of surrounding fields) */
                set_cstr(a->initial_response, sizeof a->initial_response, "");
                set_cstr(a->space2,           sizeof a->space2,           " ");
                force_keep_space2_when_empty = 1;
                break;
            case 19:  /* tab separator instead of space */
                set_cstr(a->mechanism,        sizeof a->mechanism,        "PLAIN");
                set_cstr(a->initial_response, sizeof a->initial_response, "AHVzZXIAcGFzcw==");
                set_cstr(a->space2,           sizeof a->space2,           "\t");
                break;
            default: break;
        }

        sync_space_for_auth(a, force_keep_space2_when_empty);

        mutated++;
    }

    return mutated;
}

typedef void (*helo_mutator_fn)(smtp_helo_packet_t *pkt, int num_packets);
typedef void (*ehlo_mutator_fn)(smtp_ehlo_packet_t *pkt, int num_packets);
typedef void (*mail_mutator_fn)(smtp_mail_packet_t *pkt, int num_packets);
typedef void (*rcpt_mutator_fn)(smtp_rcpt_packet_t *pkt, int num_packets);
typedef void (*vrfy_mutator_fn)(smtp_vrfy_packet_t *pkt, int num_packets);
typedef void (*expn_mutator_fn)(smtp_expn_packet_t *pkt, int num_packets);
typedef void (*help_mutator_fn)(smtp_help_packet_t *pkt, int num_packets);
typedef void (*auth_mutator_fn)(smtp_auth_packet_t *pkt, int num_packets);


typedef void (*data_mutator_fn)(smtp_data_packet_t *pkt, int num_packets);
typedef void (*rset_mutator_fn)(smtp_rset_packet_t *pkt, int num_packets);
typedef void (*noop_mutator_fn)(smtp_noop_packet_t *pkt, int num_packets);
typedef void (*quit_mutator_fn)(smtp_quit_packet_t *pkt, int num_packets);
typedef void (*starttls_mutator_fn)(smtp_starttls_packet_t *pkt, int num_packets);

static void data_nop(smtp_data_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void rset_nop(smtp_rset_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void noop_nop(smtp_noop_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void quit_nop(smtp_quit_packet_t *pkt, int n)     { (void)pkt; (void)n; }
static void starttls_nop(smtp_starttls_packet_t *pkt, int n){ (void)pkt; (void)n; }


/* HELO */
static helo_mutator_fn helo_mutators[] = {
  mutate_helo_domain,
};
/* EHLO */
static ehlo_mutator_fn ehlo_mutators[] = {
  mutate_ehlo_domain,
};
/* MAIL */
static mail_mutator_fn mail_mutators[] = {
  mutate_mail_reverse_path,
  mutate_mail_optional_args,
  add_mail_optional_args,
  delete_mail_optional_args,
};
/* RCPT */
static rcpt_mutator_fn rcpt_mutators[] = {
  mutate_rcpt_forward_path,
  mutate_rcpt_optional_args,
  add_rcpt_optional_args,
  delete_rcpt_optional_args,
};
/* VRFY */
static vrfy_mutator_fn vrfy_mutators[] = {
  mutate_vrfy_string,

};
/* EXPN */
static expn_mutator_fn expn_mutators[] = {
  mutate_expn_mailing_list,
};

static help_mutator_fn help_mutators[] = {
  mutate_smtp_help_argument,
  add_smtp_help_argument,
  delete_smtp_help_argument

};
/* AUTH */
static auth_mutator_fn auth_mutators[] = {
  mutate_auth_initial_response,
  add_auth_initial_response,
  delete_auth_initial_response,
};

static data_mutator_fn data_mutators[]         = { data_nop };
static rset_mutator_fn rset_mutators[]         = { rset_nop };
static noop_mutator_fn noop_mutators[]         = { noop_nop };
static quit_mutator_fn quit_mutators[]         = { quit_nop };
static starttls_mutator_fn starttls_mutators[] = { starttls_nop };


#define HELO_MUTATOR_COUNT      (sizeof(helo_mutators)/sizeof(helo_mutator_fn))
#define EHLO_MUTATOR_COUNT      (sizeof(ehlo_mutators)/sizeof(ehlo_mutator_fn))
#define MAIL_MUTATOR_COUNT      (sizeof(mail_mutators)/sizeof(mail_mutator_fn))
#define RCPT_MUTATOR_COUNT      (sizeof(rcpt_mutators)/sizeof(rcpt_mutator_fn))
#define VRFY_MUTATOR_COUNT      (sizeof(vrfy_mutators)/sizeof(vrfy_mutator_fn))
#define EXPN_MUTATOR_COUNT      (sizeof(expn_mutators)/sizeof(expn_mutator_fn))
#define HELP_MUTATOR_COUNT      (sizeof(help_mutators)/sizeof(help_mutator_fn))
#define AUTH_MUTATOR_COUNT      (sizeof(auth_mutators)/sizeof(auth_mutator_fn))
#define DATA_MUTATOR_COUNT      (sizeof(data_mutators)/sizeof(data_mutator_fn))
#define RSET_MUTATOR_COUNT      (sizeof(rset_mutators)/sizeof(rset_mutator_fn))
#define NOOP_MUTATOR_COUNT      (sizeof(noop_mutators)/sizeof(noop_mutator_fn))
#define QUIT_MUTATOR_COUNT      (sizeof(quit_mutators)/sizeof(quit_mutator_fn))
#define STARTTLS_MUTATOR_COUNT  (sizeof(starttls_mutators)/sizeof(starttls_mutator_fn))



static inline int rr(int n) { return (n > 0) ? rand() % n : 0; }

void dispatch_helo_mutation(smtp_helo_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  helo_mutators[rr(HELO_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_ehlo_mutation(smtp_ehlo_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  ehlo_mutators[rr(EHLO_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_mail_mutation(smtp_mail_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  mail_mutators[rr(MAIL_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_rcpt_mutation(smtp_rcpt_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  rcpt_mutators[rr(RCPT_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_vrfy_mutation(smtp_vrfy_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  vrfy_mutators[rr(VRFY_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_expn_mutation(smtp_expn_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  expn_mutators[rr(EXPN_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_help_mutation(smtp_help_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  help_mutators[rr(HELP_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_smtp_auth_mutation(smtp_auth_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  auth_mutators[rr(AUTH_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_data_mutation(smtp_data_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  data_mutators[rr(DATA_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_rset_mutation(smtp_rset_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  rset_mutators[rr(RSET_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_noop_mutation(smtp_noop_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  noop_mutators[rr(NOOP_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_quit_mutation(smtp_quit_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  quit_mutators[rr(QUIT_MUTATOR_COUNT)](pkt, 1);
}
void dispatch_starttls_mutation(smtp_starttls_packet_t *pkt, int num_packets) {
  if (!pkt) return;
  starttls_mutators[rr(STARTTLS_MUTATOR_COUNT)](pkt, 1);
}




void dispatch_smtp_multiple_mutations(smtp_packet_t *pkts, int num_packets, int rounds) {
  if (!pkts || num_packets <= 0 || rounds <= 0) return;

  for (int i = 0; i < rounds; ++i) {
    int idx = rand() % num_packets;
    switch (pkts[idx].cmd_type) {
      case SMTP_PKT_HELO:
        dispatch_helo_mutation(&pkts[idx].pkt.helo, 1);
        break;
      case SMTP_PKT_EHLO:
        dispatch_ehlo_mutation(&pkts[idx].pkt.ehlo, 1);
        break;
      case SMTP_PKT_MAIL:
        dispatch_mail_mutation(&pkts[idx].pkt.mail, 1);
        break;
      case SMTP_PKT_RCPT:
        dispatch_rcpt_mutation(&pkts[idx].pkt.rcpt, 1);
        break;
      case SMTP_PKT_DATA:
        dispatch_data_mutation(&pkts[idx].pkt.data, 1);
        break;
      case SMTP_PKT_RSET:
        dispatch_rset_mutation(&pkts[idx].pkt.rset, 1);
        break;
      case SMTP_PKT_VRFY:
        dispatch_vrfy_mutation(&pkts[idx].pkt.vrfy, 1);
        break;
      case SMTP_PKT_EXPN:
        dispatch_expn_mutation(&pkts[idx].pkt.expn, 1);
        break;
      case SMTP_PKT_HELP:
        dispatch_help_mutation(&pkts[idx].pkt.help, 1);
        break;
      case SMTP_PKT_NOOP:
        dispatch_noop_mutation(&pkts[idx].pkt.noop, 1);
        break;
      case SMTP_PKT_QUIT:
        dispatch_quit_mutation(&pkts[idx].pkt.quit, 1);
        break;
      case SMTP_PKT_STARTTLS:
        dispatch_starttls_mutation(&pkts[idx].pkt.starttls, 1);
        break;
      case SMTP_PKT_AUTH:
        dispatch_smtp_auth_mutation(&pkts[idx].pkt.auth, 1);
        break;
      case SMTP_PKT_UNRECOGNIZED:
      default:

        break;
    }
  }
}
