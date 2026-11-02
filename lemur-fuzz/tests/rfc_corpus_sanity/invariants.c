/* Semantic assertions which byte round trips alone cannot establish. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llm/dns/dns.h"
#include "llm/ssh/ssh.h"
#include "llm/tls/tls.h"
#include "llm/dicom/dicom.h"

static uint8_t *fixture(const char *name, uint32_t *len) {
    char path[256];
    snprintf(path, sizeof(path), "tests/rfc_corpus_sanity/corpus/%s.bin", name);
    FILE *f = fopen(path, "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0);
    long n = ftell(f); assert(n > 0 && n < 1048576);
    rewind(f);
    uint8_t *p = malloc((size_t)n); assert(p);
    assert(fread(p, 1, (size_t)n, f) == (size_t)n); fclose(f);
    *len = (uint32_t)n; return p;
}

int main(void) {
    uint32_t len, cap;
    uint8_t *wire = fixture("dns/boundary-rdata-8192", &len);
    dns_packet_t *dns = calloc(1, sizeof(*dns)); assert(dns);
    uint8_t *out = malloc(262144); assert(out);
    assert(parse_dns_msg(wire, len, dns, 1) == 1);
    dns->u.dns_message.wire_len = 0;
    dns->u.dns_message.header.id = 0x1234;
    cap = len;
    assert(reassemble_dns_msgs(dns, 1, out, &cap) == 0 && cap == len);
    assert(out[0] == 0x12 && out[1] == 0x34 && !memcmp(out + 2, wire + 2, len - 2));
    cap = len - 1; assert(reassemble_dns_msgs(dns, 1, out, &cap) != 0);
    dns->u.dns_message.answers[0].rdlength = 65535;
    cap = 262144; assert(reassemble_dns_msgs(dns, 1, out, &cap) == 0);
    dns_packet_t *dns2 = calloc(1, sizeof(*dns2)); assert(dns2);
    assert(parse_dns_msg(out, cap, dns2, 1) == 1);
    assert(cap == len);
    assert(dns2->u.dns_message.answers[0].rdlength == dns->u.dns_message.answers[0].rdata_overflow_len);
    free(dns2);
    free(dns); free(wire);

    wire = fixture("ssh/boundary-kex-mpint-8192", &len);
    ssh_packet_t *ssh = calloc(1, sizeof(*ssh)); assert(ssh);
    assert(parse_ssh_msg(wire, len, ssh, 1) == 1);
    assert(ssh->type == SSH_TRANSPORT_PACKET); /* No truncated mpint template. */
    ssh->wire_len = 0;
    if (ssh->type == SSH_TRANSPORT_PACKET) { ssh->u.transport.packet_length = 0xffffffffu; ssh->u.transport.padding_length = 0xff; }
    fix_ssh(ssh, 1);
    cap = 262144;
    assert(reassemble_ssh_msgs(ssh, 1, out, &cap) == 0);
    ssh_packet_t *ssh2 = calloc(1, sizeof(*ssh2)); assert(ssh2);
    assert(parse_ssh_msg(out, cap, ssh2, 1) == 1);
    free(ssh2);
    free(ssh); free(wire);

    const char *ssh_cases[] = {"ssh/kex-dh-gex-request-pad0", "ssh/kex-dh-gex-init-pad0", "ssh/auth-info-response-2-pad0"};
    for (unsigned i = 0; i < 3; i++) {
        wire = fixture(ssh_cases[i], &len);
        ssh = calloc(1, sizeof(*ssh)); assert(ssh);
        assert(parse_ssh_msg(wire, len, ssh, 1) == 1);
        ssh_packet_type_t type = ssh->type;
        ssh->wire_len = 0;
        fix_ssh(ssh, 1);
        assert(ssh->type == type); /* A known request must never be erased. */
        cap = len;
        assert(reassemble_ssh_msgs(ssh, 1, out, &cap) == 0 && cap == len && !memcmp(wire, out, len));
        free(ssh); free(wire);
    }

    wire = fixture("tls/boundary-fragment-with-following", &len);
    tls_packet_t *tls = calloc(2, sizeof(*tls)); assert(tls);
    assert(parse_tls_msg(wire, len, tls, 2) == 2);
    assert(tls[1].u.handshake.is_fragment);
    assert(tls[1].u.handshake.following_handshake_count == 1);
    const tls_coalesced_handshake_t *h = &tls[1].u.handshake.following[0];
    assert(h->wire == wire + len - 5 && h->wire_len == 5);
    assert(h->wire[0] == TLS_HANDSHAKE_KEY_UPDATE && h->wire[4] == 1);
    assert(parse_tls_msg(wire, len, tls, 1) == 0); /* No silent prefix success. */
    /* The bounded annotation buffer may only copy a prefix of the last record. */
    uint8_t *large = calloc(1, 12 + 5 + 18432); assert(large);
    memcpy(large, wire, len);
    large[15] = 0x48; large[16] = 0x00;
    assert(parse_tls_msg(large, 12 + 5 + 18432, tls, 2) == 2);
    assert(tls[1].u.handshake.following_handshake_count > 0);
    assert(tls[1].u.handshake.following[0].wire == large + len - 5);
    assert(tls[1].u.handshake.following[0].wire[0] == TLS_HANDSHAKE_KEY_UPDATE);
    tls[1].u.handshake.record.length = 0xffff;
    tls[1].u.handshake.handshake.length.b0 = 0xff;
    tls[1].u.handshake.handshake.length.b1 = 0xff;
    tls[1].u.handshake.handshake.length.b2 = 0xff;
    cap = 262144; assert(reassemble_tls_msgs(&tls[1], 1, out, &cap) == 0);
    assert(((uint32_t)out[3] << 8 | out[4]) == cap - 5);
    assert(parse_tls_msg(out, cap, tls, 1) == 1);
    free(large);
    free(tls); free(wire);

    wire = fixture("dicom/assoc-user-item-4", &len);
    dicom_packet_t *dicom = calloc(1, sizeof(*dicom)); assert(dicom);
    assert(parse_dicom_msg(wire, len, dicom, 1) == 1);
    assert(dicom->type == DICOM_PKT_A_ASSOCIATE_RQ);
    dicom_user_info_item_t *ui = &dicom->u.a_associate_rq.user_info;
    assert(ui->has_sop_class_common_extended_negotiation);
    assert(ui->related_general_sop_class_uid_count == 1);
    assert(ui->related_general_sop_class_uids[0].length == ui->sop_class_common_sop_uid.length);
    assert(!memcmp(ui->related_general_sop_class_uids[0].value,
                   ui->sop_class_common_sop_uid.value, ui->sop_class_common_sop_uid.length));
    dicom->raw_length = 0;
    dicom->u.a_associate_rq.pdu_length = 0xffffffffu;
    dicom->u.a_associate_rq.application_context.application_context_name.length = 0xffff;
    cap = 262144; assert(reassemble_dicom_msgs(dicom, 1, out, &cap) == 0);
    assert(((uint32_t)out[2] << 24 | (uint32_t)out[3] << 16 | (uint32_t)out[4] << 8 | out[5]) == cap - 6);
    dicom_packet_t *dicom2 = calloc(1, sizeof(*dicom2)); assert(dicom2);
    assert(parse_dicom_msg(out, cap, dicom2, 1) == 1);
    assert(dicom2->u.a_associate_rq.application_context.application_context_name.length <= DICOM_MAX_UID_LEN);
    free(dicom2);
    free(dicom); free(wire); free(out);
    puts("protocol metadata and bounded-output invariants: OK");
    return 0;
}
