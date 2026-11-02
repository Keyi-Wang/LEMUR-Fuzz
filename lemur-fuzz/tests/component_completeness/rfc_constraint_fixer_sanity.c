#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "ssh.h"
#include "tls.h"
#include "dicom.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
  if (!(cond)) { fprintf(stderr, "[FAIL] %s\n", msg); failures++; return 0; } \
} while (0)

static int test_dns_fixers(void) {
  dns_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.type = DNS_MESSAGE;
  dns_message_t *m = &pkt.u.dns_message;
  m->header.qr = 1;
  m->header.opcode = 5; /* UPDATE */
  m->header.aa = 1;
  m->header.ra = 1;
  m->header.z = 7;
  m->header.rcode = 9;
  m->question_count = 0;
  m->answer_count = 1;
  m->answers[0].present = 1;
  m->answers[0].name_len = 2;
  m->answers[0].name[0] = 0xc0; /* invalid compression pointer in fixer output */
  m->answers[0].name[1] = 0;
  m->answers[0].rdata_len = 3;
  m->answers[0].rdlength = 99;
  m->has_opt = 1;
  m->opt_rr.present = 1;
  m->opt_rr.name_len = 2;
  m->opt_rr.name[0] = 3;
  m->opt_rr.name[1] = 'x';
  m->opt_rr.type = 1;
  m->opt_rr.udp_payload_size = 1;
  m->opt_rr.edns_flags = 0x7fff;
  m->opt_rr.rdata_len = 4;
  m->opt_rr.rdlength = 10;

  fix_dns(&pkt, 1);
  CHECK(m->header.qr == 0, "DNS QR not fixed to query");
  CHECK(m->header.opcode == 5, "DNS UPDATE opcode not preserved as known request opcode");
  CHECK(m->header.aa == 0 && m->header.ra == 0 && m->header.z == 0 && m->header.rcode == 0,
        "DNS response-only/reserved header bits not fixed");
  CHECK(m->question_count == 1 && m->questions[0].qtype == 6 && m->questions[0].present,
        "DNS UPDATE Zone question not synthesized as SOA");
  CHECK(m->header.qdcount == m->question_count && m->header.ancount == m->answer_count,
        "DNS section counts not synchronized");
  CHECK(m->answers[0].name_len == 1 && m->answers[0].name[0] == 0,
        "DNS invalid RR name not normalized");
  CHECK(m->answers[0].rdlength == m->answers[0].rdata_len,
        "DNS RR rdlength not synchronized");
  CHECK(m->opt_rr.name_len == 1 && m->opt_rr.name[0] == 0 && m->opt_rr.type == 41,
        "DNS OPT shape not fixed");
  CHECK(m->opt_rr.udp_payload_size >= 512 && m->opt_rr.edns_flags == 0,
        "DNS OPT payload size/flags not fixed");
  CHECK(m->opt_rr.rdlength == m->opt_rr.rdata_len,
        "DNS OPT rdlength not synchronized");
  return 1;
}

static int test_ssh_fixers(void) {
  ssh_packet_t pkts[9];
  memset(pkts, 0, sizeof(pkts));
  pkts[0].type = SSH_TRANSPORT_PACKET;
  pkts[0].u.transport.packet_length = 2;
  pkts[0].u.transport.padding_length = 1;
  pkts[0].u.transport.payload_len = 1;
  pkts[0].u.transport.has_message_code = 1;
  pkts[0].u.transport.message_code = SSH_MSG_IGNORE;

  pkts[1].type = SSH_KEXINIT;
  pkts[1].u.kexinit.message_code = 0;
  pkts[1].u.kexinit.reserved_zero = 123;
  pkts[1].u.kexinit.first_kex_packet_follows = 9;

  pkts[2].type = SSH_SERVICE_REQUEST;
  pkts[2].u.service_request.message_code = 0;
  memcpy(pkts[2].u.service_request.service_name, "bad", 3);
  pkts[2].u.service_request.service_name_len = 3;

  pkts[3].type = SSH_KEXDH_INIT;
  pkts[3].u.kexdh_init.message_code = 0;
  pkts[3].u.kexdh_init.e_len = 0;

  pkts[4].type = SSH_USERAUTH_REQUEST;
  pkts[4].u.typed.field_schema = SSH_MSG_USERAUTH_REQUEST;
  pkts[4].u.typed.message_code = SSH_MSG_USERAUTH_REQUEST;
  pkts[4].u.typed.string_count = 3;
  memcpy(pkts[4].u.typed.strings[0].bytes, "u", 1); pkts[4].u.typed.strings[0].len = 1;
  memcpy(pkts[4].u.typed.strings[1].bytes, "bad-service", 11); pkts[4].u.typed.strings[1].len = 11;
  memcpy(pkts[4].u.typed.strings[2].bytes, "bad-method", 10); pkts[4].u.typed.strings[2].len = 10;

  pkts[5].type = SSH_CHANNEL_OPEN;
  pkts[5].u.typed.field_schema = SSH_MSG_CHANNEL_OPEN;
  pkts[5].u.typed.message_code = SSH_MSG_CHANNEL_OPEN;
  pkts[5].u.typed.string_count = 1;
  memcpy(pkts[5].u.typed.strings[0].bytes, "session", 7); pkts[5].u.typed.strings[0].len = 7;
  pkts[5].u.typed.uint32_count = 3;
  pkts[5].u.typed.uint32_values[0] = 7;

  pkts[6].type = SSH_CHANNEL_DATA;
  pkts[6].u.typed.field_schema = SSH_MSG_CHANNEL_DATA;
  pkts[6].u.typed.message_code = SSH_MSG_CHANNEL_DATA;
  pkts[6].u.typed.uint32_count = 1;
  pkts[6].u.typed.uint32_values[0] = 99;

  pkts[7].type = SSH_NEWKEYS;
  pkts[7].u.newkeys.message_code = 0;

  pkts[8].type = SSH_CHANNEL_REQUEST;
  pkts[8].u.typed.field_schema = SSH_MSG_CHANNEL_REQUEST;
  pkts[8].u.typed.message_code = SSH_MSG_CHANNEL_REQUEST;

  fix_ssh(pkts, 9);
  CHECK(pkts[0].u.transport.padding_length >= 4, "SSH transport padding < 4");
  CHECK(((pkts[0].u.transport.packet_length + 4u) % 8u) == 0,
        "SSH transport packet length not block aligned");
  CHECK(pkts[0].u.transport.packet_length == 1u + pkts[0].u.transport.payload_len + pkts[0].u.transport.padding_length,
        "SSH transport packet_length formula not fixed");
  CHECK(pkts[1].u.kexinit.message_code == SSH_MSG_KEXINIT && pkts[1].u.kexinit.reserved_zero == 0 &&
        pkts[1].u.kexinit.kex_algorithms_len > 0 && pkts[1].u.kexinit.compression_algorithms_client_to_server_len > 0,
        "SSH KEXINIT constraints not fixed");
  CHECK(pkts[2].u.service_request.message_code == SSH_MSG_SERVICE_REQUEST &&
        pkts[2].u.service_request.service_name_len == 12 &&
        memcmp(pkts[2].u.service_request.service_name, "ssh-userauth", 12) == 0,
        "SSH SERVICE_REQUEST name not fixed");
  CHECK(pkts[3].u.kexdh_init.message_code == SSH_MSG_KEXDH_INIT && pkts[3].u.kexdh_init.e_len == 1,
        "SSH KEXDH_INIT mpint not fixed");
  CHECK(pkts[4].u.typed.string_count >= 3 && pkts[4].u.typed.strings[1].len == 14 &&
        memcmp(pkts[4].u.typed.strings[1].bytes, "ssh-connection", 14) == 0 &&
        pkts[4].u.typed.strings[2].len == 4 && memcmp(pkts[4].u.typed.strings[2].bytes, "none", 4) == 0,
        "SSH typed USERAUTH_REQUEST schema not fixed");
  CHECK(pkts[6].u.typed.uint32_count >= 1 && pkts[6].u.typed.uint32_values[0] == 7,
        "SSH channel recipient id not synchronized across sequence");
  CHECK(pkts[7].u.newkeys.message_code == SSH_MSG_NEWKEYS,
        "SSH NEWKEYS code not fixed");
  CHECK(pkts[8].type == SSH_OPAQUE && pkts[8].u.opaque.len == 0,
        "SSH cleartext packet after NEWKEYS not dropped");
  return 1;
}


static int test_ssh_gex_kex_sequence_fix(void) {
  ssh_packet_t *pkts = (ssh_packet_t *)calloc(3, sizeof(*pkts));
  ssh_packet_t *reparsed = (ssh_packet_t *)calloc(3, sizeof(*reparsed));
  uint8_t *out = (uint8_t *)calloc(1, 8192);
  CHECK(pkts != NULL && reparsed != NULL && out != NULL,
        "SSH GEX test allocation failed");

  pkts[0].type = SSH_KEXINIT;
  pkts[0].u.kexinit.message_code = SSH_MSG_KEXINIT;
  memcpy(pkts[0].u.kexinit.kex_algorithms,
         "diffie-hellman-group-exchange-sha256", 36);
  pkts[0].u.kexinit.kex_algorithms_len = 36;

  pkts[1].type = SSH_KEXDH_INIT;
  pkts[1].u.kexdh_init.message_code = SSH_MSG_KEXDH_INIT;
  pkts[1].u.kexdh_init.e_len = 1;
  pkts[1].u.kexdh_init.e[0] = 1;

  pkts[2].type = SSH_NEWKEYS;

  fix_ssh(pkts, 3);
  CHECK(pkts[1].type == SSH_KEX_DH_GEX_REQUEST,
        "SSH GEX KEXINIT did not convert following KEXDH_INIT to GEX_REQUEST");
  CHECK(pkts[1].u.typed.message_code == SSH_MSG_KEX_DH_GEX_REQUEST &&
        pkts[1].u.typed.field_schema == SSH_MSG_KEX_DH_GEX_REQUEST &&
        pkts[1].u.typed.uint32_count >= 3 &&
        pkts[1].u.typed.uint32_values[0] <= pkts[1].u.typed.uint32_values[1] &&
        pkts[1].u.typed.uint32_values[1] <= pkts[1].u.typed.uint32_values[2],
        "SSH GEX_REQUEST bounds not synthesized correctly");

  uint32_t out_len = 8192;
  CHECK(reassemble_ssh_msgs(pkts, 3, out, &out_len) == 0 && out_len > 0,
        "SSH GEX fixed sequence did not reassemble");

  size_t reparsed_count = parse_ssh_msg(out, out_len, reparsed, 3);
  CHECK(reparsed_count >= 2,
        "SSH GEX fixed sequence did not parse after reassemble");
  CHECK(reparsed[1].type == SSH_KEX_DH_GEX_REQUEST &&
        reparsed[1].u.typed.uint32_count >= 3,
        "SSH GEX_REQUEST was not preserved by parse(reassemble(.))");
  free(out);
  free(reparsed);
  free(pkts);
  return 1;
}

static int test_tls_fixers(void) {
  tls_packet_t pkts[3];
  memset(pkts, 0, sizeof(pkts));
  pkts[0].type = TLS_PACKET_ALERT;
  pkts[0].u.alert.record.type = 0;
  pkts[0].u.alert.record.version.major = 1;
  pkts[0].u.alert.record.version.minor = 9;
  pkts[0].u.alert.record.length = 99;
  pkts[0].u.alert.alert.level = 9;
  pkts[0].u.alert.alert.description = 9;

  pkts[1].type = TLS_PACKET_HANDSHAKE;
  pkts[1].u.handshake.has_client_hello = 1;
  pkts[1].u.handshake.client_hello.client_version.major = 1;
  pkts[1].u.handshake.client_hello.client_version.minor = 0;
  pkts[1].u.handshake.client_hello.session_id_len = 99;
  pkts[1].u.handshake.client_hello.cipher_suites_len = 1;
  pkts[1].u.handshake.client_hello.compression_methods_len = 1;
  pkts[1].u.handshake.client_hello.compression_methods[0] = 1;
  pkts[1].u.handshake.client_hello.extensions_len = 3;

  pkts[2].type = TLS_PACKET_APPLICATION_DATA;
  pkts[2].u.application_data.record.version.major = 9;
  pkts[2].u.application_data.app_data.data_len = 20000;

  fix_tls(pkts, 3);
  CHECK(pkts[0].u.alert.record.type == TLS_CONTENTTYPE_ALERT && pkts[0].u.alert.record.length == 2,
        "TLS alert record type/length not fixed");
  CHECK(pkts[0].u.alert.record.version.major == 3 && pkts[0].u.alert.record.version.minor == 3,
        "TLS record version not fixed");
  CHECK(pkts[0].u.alert.alert.level == TLS_ALERT_LEVEL_FATAL && pkts[0].u.alert.alert.description == TLS_ALERT_DECODE_ERROR,
        "TLS alert enums not fixed");
  CHECK(pkts[1].u.handshake.record.type == TLS_CONTENTTYPE_HANDSHAKE &&
        pkts[1].u.handshake.handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO,
        "TLS ClientHello handshake header not fixed");
  CHECK(pkts[1].u.handshake.client_hello.client_version.major == 3 && pkts[1].u.handshake.client_hello.client_version.minor == 3,
        "TLS ClientHello version not fixed");
  CHECK(pkts[1].u.handshake.client_hello.session_id_len == TLS_MAX_SESSION_ID_LEN &&
        pkts[1].u.handshake.client_hello.cipher_suites_len >= 8 &&
        pkts[1].u.handshake.client_hello.compression_methods[0] == 0 &&
        pkts[1].u.handshake.client_hello.extensions_len == 0,
        "TLS ClientHello vector constraints not fixed");
  CHECK(pkts[2].u.application_data.record.type == TLS_CONTENTTYPE_APPLICATION_DATA &&
        pkts[2].u.application_data.app_data.data_len == 16384,
        "TLS application_data length not fixed");
  return 1;
}

static int test_dicom_fixers(void) {
  dicom_packet_t *pkts = (dicom_packet_t *)calloc(4, sizeof(*pkts));
  CHECK(pkts != NULL, "DICOM allocation failed");

  pkts[0].type = DICOM_PKT_A_ASSOCIATE_RQ;
  pkts[0].u.a_associate_rq.protocol_version = 99;
  pkts[0].u.a_associate_rq.reserved2 = 7;
  pkts[0].u.a_associate_rq.presentation_context_count = 0;

  pkts[1].type = DICOM_PKT_P_DATA_TF;
  pkts[1].u.p_data_tf.pdv_count = 0;

  pkts[2].type = DICOM_PKT_A_ASSOCIATE_RJ;
  pkts[2].u.a_associate_rj.result = 9;
  pkts[2].u.a_associate_rj.source = 9;
  pkts[2].u.a_associate_rj.reason_diag = 9;

  pkts[3].type = DICOM_PKT_A_ABORT;
  pkts[3].u.a_abort.source = 9;
  pkts[3].u.a_abort.reason_diag = 9;

  fix_dicom(pkts, 4);
  CHECK(pkts[0].u.a_associate_rq.pdu_type == DICOM_PDU_A_ASSOCIATE_RQ &&
        pkts[0].u.a_associate_rq.protocol_version == 1 && pkts[0].u.a_associate_rq.reserved2 == 0,
        "DICOM A-ASSOCIATE-RQ fixed header not fixed");
  CHECK(pkts[0].u.a_associate_rq.application_context.item_type == 0x10 &&
        pkts[0].u.a_associate_rq.application_context.item_length > 0 &&
        pkts[0].u.a_associate_rq.presentation_context_count == 1 &&
        pkts[0].u.a_associate_rq.presentation_contexts[0].presentation_context_id == 1 &&
        pkts[0].u.a_associate_rq.presentation_contexts[0].transfer_syntax_count == 1,
        "DICOM A-ASSOCIATE-RQ required items not fixed");
  CHECK(pkts[1].u.p_data_tf.pdv_count == 1 && pkts[1].u.p_data_tf.pdvs[0].pdv_length == 2 &&
        (pkts[1].u.p_data_tf.pdvs[0].control_header & DICOM_PDV_FLAG_LAST_FRAGMENT),
        "DICOM P-DATA-TF PDV constraints not fixed");
  CHECK(pkts[2].u.a_associate_rj.pdu_length == 4 && pkts[2].u.a_associate_rj.result == 1 &&
        pkts[2].u.a_associate_rj.source == 1 && pkts[2].u.a_associate_rj.reason_diag == 1,
        "DICOM A-ASSOCIATE-RJ enums not fixed");
  CHECK(pkts[3].u.a_abort.pdu_length == 4 && pkts[3].u.a_abort.source == 2 &&
        pkts[3].u.a_abort.reason_diag == 2,
        "DICOM A-ABORT source/reason not fixed");
  free(pkts);
  return 1;
}

int main(void) {
  int ok = 1;
  ok &= test_dns_fixers();
  ok &= test_ssh_fixers();
  ok &= test_ssh_gex_kex_sequence_fix();
  ok &= test_tls_fixers();
  ok &= test_dicom_fixers();
  if (!ok || failures) {
    fprintf(stderr, "rfc_constraint_fixer_sanity failed failures=%d\n", failures);
    return 1;
  }
  puts("rfc_constraint_fixer_sanity: PASS");
  return 0;
}
