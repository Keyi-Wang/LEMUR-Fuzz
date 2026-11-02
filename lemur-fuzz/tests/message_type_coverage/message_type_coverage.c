#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "ssh.h"
#include "tls.h"
#include "dicom.h"

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
  if (!(cond)) { \
    fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__); \
    failures++; \
    return 0; \
  } \
} while (0)

static void put_u16_be(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static void put_u24_be(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 16);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)v;
}

static void put_u32_be(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void put_u16_le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}

static void put_u32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static int test_dns(void) {
  uint8_t dns_query[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01
  };
  dns_packet_t pkts[4];
  memset(pkts, 0, sizeof(pkts));
  size_t n = parse_dns_msg(dns_query, (uint32_t)sizeof(dns_query), pkts, 4);
  CHECK(n == 1 && pkts[0].type == DNS_MESSAGE, "DNS query parse/classification failed");
  fix_dns(pkts, (int)n);
  uint8_t out[1024];
  uint32_t out_len = sizeof(out);
  CHECK(reassemble_dns_msgs(pkts, (uint32_t)n, out, &out_len) == 0 && out_len > 0,
        "DNS reassemble failed");
  memset(pkts, 0, sizeof(pkts));
  n = parse_dns_msg(out, out_len, pkts, 4);
  CHECK(n == 1 && pkts[0].type == DNS_MESSAGE, "DNS roundtrip parse failed");
  return 1;
}

static uint32_t ssh_wrap_payload(const uint8_t *payload, uint32_t payload_len, uint8_t *out) {
  const uint32_t block = 8;
  uint32_t min_pad = 4;
  uint32_t no_mac_total = 1 + payload_len + min_pad;
  uint32_t rem = no_mac_total % block;
  uint32_t padding_len = rem ? (block - rem) : block;
  if (padding_len < 4) padding_len += block;
  uint32_t packet_length = 1 + payload_len + padding_len;
  put_u32_be(out, packet_length);
  out[4] = (uint8_t)padding_len;
  memcpy(out + 5, payload, payload_len);
  memset(out + 5 + payload_len, 0, padding_len);
  return 4 + packet_length;
}

static uint32_t ssh_payload_kexinit(uint8_t *payload) {
  uint32_t off = 0;
  payload[off++] = SSH_MSG_KEXINIT;
  memset(payload + off, 0x42, 16); off += 16;
  for (int i = 0; i < 10; i++) { put_u32_be(payload + off, 0); off += 4; }
  payload[off++] = 0;
  put_u32_be(payload + off, 0); off += 4;
  return off;
}

static uint32_t ssh_payload_kexdh_init(uint8_t *payload) {
  uint32_t off = 0;
  payload[off++] = SSH_MSG_KEXDH_INIT;
  put_u32_be(payload + off, 1); off += 4;
  payload[off++] = 1;
  return off;
}

static uint32_t ssh_payload_service_request(uint8_t *payload) {
  static const char service[] = "ssh-userauth";
  uint32_t off = 0;
  payload[off++] = SSH_MSG_SERVICE_REQUEST;
  put_u32_be(payload + off, (uint32_t)strlen(service)); off += 4;
  memcpy(payload + off, service, strlen(service)); off += (uint32_t)strlen(service);
  return off;
}

static int test_ssh_payload(const char *name, const uint8_t *payload, uint32_t payload_len,
                            ssh_packet_type_t expected_type) {
  uint8_t wire[4096];
  uint32_t wire_len = ssh_wrap_payload(payload, payload_len, wire);
  ssh_packet_t pkts[8];
  memset(pkts, 0, sizeof(pkts));
  size_t n = parse_ssh_msg(wire, wire_len, pkts, 8);
  CHECK(n == 1, "SSH %s parsed packet count=%zu", name, n);
  CHECK(pkts[0].type == expected_type, "SSH %s expected type %d got %d", name, expected_type, pkts[0].type);
  dispatch_ssh_multiple_mutations(pkts, (unsigned int)n, 1);
  fix_ssh(pkts, (int)n);
  uint8_t out[65536];
  uint32_t out_len = sizeof(out);
  CHECK(reassemble_ssh_msgs(pkts, (uint32_t)n, out, &out_len) == 0 && out_len > 0,
        "SSH %s reassemble failed", name);
  memset(pkts, 0, sizeof(pkts));
  n = parse_ssh_msg(out, out_len, pkts, 8);
  CHECK(n > 0, "SSH %s roundtrip parse failed", name);
  return 1;
}

static int test_ssh(void) {
  ssh_packet_t pkts[4];
  const uint8_t banner[] = "SSH-2.0-LemurFuzz\r\n";
  memset(pkts, 0, sizeof(pkts));
  size_t n = parse_ssh_msg(banner, (uint32_t)sizeof(banner) - 1, pkts, 4);
  CHECK(n == 1 && pkts[0].type == SSH_BANNER, "SSH banner parse failed");

  uint8_t payload[256];
  uint32_t len = ssh_payload_kexinit(payload);
  if (!test_ssh_payload("KEXINIT", payload, len, SSH_KEXINIT)) return 0;
  len = ssh_payload_kexdh_init(payload);
  if (!test_ssh_payload("KEXDH_INIT", payload, len, SSH_KEXDH_INIT)) return 0;
  len = ssh_payload_service_request(payload);
  if (!test_ssh_payload("SERVICE_REQUEST", payload, len, SSH_SERVICE_REQUEST)) return 0;
  payload[0] = SSH_MSG_NEWKEYS;
  if (!test_ssh_payload("NEWKEYS", payload, 1, SSH_NEWKEYS)) return 0;

  struct ssh_case { uint8_t code; ssh_packet_type_t type; const char *name; } cases[] = {
    {SSH_MSG_DISCONNECT, SSH_DISCONNECT, "DISCONNECT"},
    {SSH_MSG_IGNORE, SSH_IGNORE, "IGNORE"},
    {SSH_MSG_UNIMPLEMENTED, SSH_UNIMPLEMENTED, "UNIMPLEMENTED"},
    {SSH_MSG_DEBUG, SSH_DEBUG, "DEBUG"},
    {SSH_MSG_SERVICE_ACCEPT, SSH_SERVICE_ACCEPT, "SERVICE_ACCEPT"},
    {SSH_MSG_KEXDH_REPLY, SSH_KEXDH_REPLY, "KEXDH_REPLY"},
    {SSH_MSG_USERAUTH_REQUEST, SSH_USERAUTH_REQUEST, "USERAUTH_REQUEST"},
    {SSH_MSG_USERAUTH_FAILURE, SSH_USERAUTH_FAILURE, "USERAUTH_FAILURE"},
    {SSH_MSG_USERAUTH_SUCCESS, SSH_USERAUTH_SUCCESS, "USERAUTH_SUCCESS"},
    {SSH_MSG_USERAUTH_BANNER, SSH_USERAUTH_BANNER, "USERAUTH_BANNER"},
    {SSH_MSG_USERAUTH_METHOD_REPLY, SSH_USERAUTH_METHOD_REPLY, "USERAUTH_METHOD_REPLY"},
    {SSH_MSG_GLOBAL_REQUEST, SSH_GLOBAL_REQUEST, "GLOBAL_REQUEST"},
    {SSH_MSG_REQUEST_SUCCESS, SSH_REQUEST_SUCCESS, "REQUEST_SUCCESS"},
    {SSH_MSG_REQUEST_FAILURE, SSH_REQUEST_FAILURE, "REQUEST_FAILURE"},
    {SSH_MSG_CHANNEL_OPEN, SSH_CHANNEL_OPEN, "CHANNEL_OPEN"},
    {SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_CHANNEL_OPEN_CONFIRMATION, "CHANNEL_OPEN_CONFIRMATION"},
    {SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_CHANNEL_OPEN_FAILURE, "CHANNEL_OPEN_FAILURE"},
    {SSH_MSG_CHANNEL_WINDOW_ADJUST, SSH_CHANNEL_WINDOW_ADJUST, "CHANNEL_WINDOW_ADJUST"},
    {SSH_MSG_CHANNEL_DATA, SSH_CHANNEL_DATA, "CHANNEL_DATA"},
    {SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_CHANNEL_EXTENDED_DATA, "CHANNEL_EXTENDED_DATA"},
    {SSH_MSG_CHANNEL_EOF, SSH_CHANNEL_EOF, "CHANNEL_EOF"},
    {SSH_MSG_CHANNEL_CLOSE, SSH_CHANNEL_CLOSE, "CHANNEL_CLOSE"},
    {SSH_MSG_CHANNEL_REQUEST, SSH_CHANNEL_REQUEST, "CHANNEL_REQUEST"},
    {SSH_MSG_CHANNEL_SUCCESS, SSH_CHANNEL_SUCCESS, "CHANNEL_SUCCESS"},
    {SSH_MSG_CHANNEL_FAILURE, SSH_CHANNEL_FAILURE, "CHANNEL_FAILURE"}
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    payload[0] = cases[i].code;
    if (!test_ssh_payload(cases[i].name, payload, 1, cases[i].type)) return 0;
  }
  payload[0] = 255;
  if (!test_ssh_payload("UNKNOWN_TRANSPORT", payload, 1, SSH_TRANSPORT_PACKET)) return 0;
  return 1;
}

static int test_tls_record(uint8_t content_type, const uint8_t *frag, uint16_t frag_len,
                           tls_packet_type_t expected, const char *name) {
  uint8_t wire[256];
  wire[0] = content_type;
  wire[1] = 3;
  wire[2] = 3;
  put_u16_be(wire + 3, frag_len);
  if (frag_len) memcpy(wire + 5, frag, frag_len);

  tls_packet_t pkts[4];
  memset(pkts, 0, sizeof(pkts));
  size_t n = parse_tls_msg(wire, (uint32_t)(5 + frag_len), pkts, 4);
  CHECK(n == 1 && pkts[0].type == expected, "TLS %s parse/type failed", name);
  dispatch_tls_multiple_mutations(pkts, (int)n, 1);
  fix_tls(pkts, (int)n);
  uint8_t out[65536];
  uint32_t out_len = sizeof(out);
  CHECK(reassemble_tls_msgs(pkts, (uint32_t)n, out, &out_len) == 0 && out_len > 0,
        "TLS %s reassemble failed", name);
  memset(pkts, 0, sizeof(pkts));
  n = parse_tls_msg(out, out_len, pkts, 4);
  CHECK(n == 1, "TLS %s roundtrip parse failed", name);
  return 1;
}

static int test_tls(void) {
  uint8_t ccs[] = {1};
  uint8_t alert[] = {TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE};
  uint8_t app[] = {0xaa, 0xbb, 0xcc};
  if (!test_tls_record(TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC, ccs, sizeof(ccs), TLS_PACKET_CHANGE_CIPHER_SPEC, "CCS")) return 0;
  if (!test_tls_record(TLS_CONTENTTYPE_ALERT, alert, sizeof(alert), TLS_PACKET_ALERT, "ALERT")) return 0;
  if (!test_tls_record(TLS_CONTENTTYPE_APPLICATION_DATA, app, sizeof(app), TLS_PACKET_APPLICATION_DATA, "APPDATA")) return 0;

  uint8_t hs[4];
  uint8_t handshake_types[] = {
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
  for (size_t i = 0; i < sizeof(handshake_types) / sizeof(handshake_types[0]); i++) {
    hs[0] = handshake_types[i];
    put_u24_be(hs + 1, 0);
    if (!test_tls_record(TLS_CONTENTTYPE_HANDSHAKE, hs, sizeof(hs), TLS_PACKET_HANDSHAKE, "HANDSHAKE")) return 0;
  }

  /* Changing ClientHello fields invalidates all captured TLS 1.3 ciphertext
   * that follows it.  The semantic TLS mutator must therefore retain the
   * cleartext ClientHello and truncate at the first protected record. */
  uint8_t transcript[128];
  memset(transcript, 0, sizeof(transcript));
  uint32_t off = 0;
  transcript[off++] = TLS_CONTENTTYPE_HANDSHAKE;
  transcript[off++] = 3; transcript[off++] = 3;
  put_u16_be(transcript + off, 47); off += 2;
  transcript[off++] = TLS_HANDSHAKE_CLIENT_HELLO;
  put_u24_be(transcript + off, 43); off += 3;
  transcript[off++] = 3; transcript[off++] = 3;
  for (uint8_t i = 0; i < 32; i++) transcript[off++] = i;
  transcript[off++] = 0;                         /* session_id */
  put_u16_be(transcript + off, 2); off += 2;
  transcript[off++] = 0; transcript[off++] = 0x2f; /* TLS_RSA_WITH_AES_128_CBC_SHA */
  transcript[off++] = 1; transcript[off++] = 0;    /* compression */
  put_u16_be(transcript + off, 0); off += 2;       /* extensions */
  transcript[off++] = TLS_CONTENTTYPE_CHANGE_CIPHER_SPEC;
  transcript[off++] = 3; transcript[off++] = 3;
  put_u16_be(transcript + off, 1); off += 2; transcript[off++] = 1;
  transcript[off++] = TLS_CONTENTTYPE_APPLICATION_DATA;
  transcript[off++] = 3; transcript[off++] = 3;
  put_u16_be(transcript + off, 4); off += 2;
  transcript[off++] = 0xde; transcript[off++] = 0xad;
  transcript[off++] = 0xbe; transcript[off++] = 0xef;

  static tls_packet_t protected_pkts[4];
  memset(protected_pkts, 0, sizeof(protected_pkts));
  size_t transcript_n = parse_tls_msg(transcript, off, protected_pkts, 4);
  CHECK(transcript_n == 3 && protected_pkts[0].type == TLS_PACKET_HANDSHAKE,
        "TLS encrypted-tail fixture parse failed");
  setenv("LEMUR_TLS_TAIL_DROP_PCT", "100", 1);
  dispatch_tls_multiple_mutations(protected_pkts, (int)transcript_n, 1);
  fix_tls(protected_pkts, (int)transcript_n);
  uint8_t mutated[65536];
  uint32_t mutated_len = sizeof(mutated);
  CHECK(reassemble_tls_msgs(protected_pkts, (uint32_t)transcript_n,
                            mutated, &mutated_len) == 0 && mutated_len > 5,
        "TLS encrypted-tail fixture reassemble failed");
  CHECK(mutated[0] == TLS_CONTENTTYPE_HANDSHAKE,
        "TLS semantic mutation did not retain the cleartext ClientHello");
  static tls_packet_t reparsed_tail[4];
  memset(reparsed_tail, 0, sizeof(reparsed_tail));
  size_t reparsed_n = parse_tls_msg(mutated, mutated_len, reparsed_tail, 4);
  CHECK(reparsed_n == 2 && reparsed_tail[0].type == TLS_PACKET_HANDSHAKE &&
        reparsed_tail[1].type == TLS_PACKET_ALERT &&
        reparsed_tail[1].u.alert.alert.level == TLS_ALERT_LEVEL_FATAL,
        "TLS semantic mutation did not end with a cleartext termination alert");
  return 1;
}

static uint32_t dicom_assoc_fixed(uint8_t pdu_type, uint8_t *wire) {
  uint32_t body_len = 68;
  wire[0] = pdu_type;
  wire[1] = 0;
  put_u32_be(wire + 2, body_len);
  wire[6] = 0;
  wire[7] = 1;
  wire[8] = 0;
  wire[9] = 0;
  memset(wire + 10, ' ', 32);
  memset(wire + 42, 0, 32);
  return 6 + body_len;
}

static uint32_t dicom_assoc_rq(uint8_t *wire) {
  static const char appctx[] = "1.2.840.10008.3.1.1.1";
  uint32_t base = dicom_assoc_fixed(DICOM_PDU_A_ASSOCIATE_RQ, wire);
  uint32_t off = base;
  wire[off++] = 0x10;
  wire[off++] = 0;
  put_u16_be(wire + off, (uint16_t)strlen(appctx)); off += 2;
  memcpy(wire + off, appctx, strlen(appctx)); off += (uint32_t)strlen(appctx);
  put_u32_be(wire + 2, off - 6);
  return off;
}

static uint32_t dicom_fixed4(uint8_t pdu_type, uint8_t b6, uint8_t b7, uint8_t b8, uint8_t b9, uint8_t *wire) {
  wire[0] = pdu_type;
  wire[1] = 0;
  put_u32_be(wire + 2, 4);
  wire[6] = b6;
  wire[7] = b7;
  wire[8] = b8;
  wire[9] = b9;
  return 10;
}

static void dicom_cmd_us(uint8_t *wire, uint32_t *off, uint16_t elem, uint16_t value) {
  put_u16_le(wire + *off, 0x0000); *off += 2;
  put_u16_le(wire + *off, elem); *off += 2;
  put_u32_le(wire + *off, 2); *off += 4;
  put_u16_le(wire + *off, value); *off += 2;
}

static void dicom_cmd_text(uint8_t *wire, uint32_t *off, uint16_t elem, const char *value) {
  size_t len = strlen(value) + 1;
  put_u16_le(wire + *off, 0x0000); *off += 2;
  put_u16_le(wire + *off, elem); *off += 2;
  put_u32_le(wire + *off, (uint32_t)len); *off += 4;
  memcpy(wire + *off, value, len);
  *off += (uint32_t)len;
}

static uint32_t dicom_p_data_echo_command(uint8_t *wire) {
  uint8_t cmd[256];
  uint32_t coff = 0;
  put_u16_le(cmd + coff, 0x0000); coff += 2;
  put_u16_le(cmd + coff, 0x0000); coff += 2;
  put_u32_le(cmd + coff, 4); coff += 4;
  put_u32_le(cmd + coff, 0); coff += 4; /* patched as group length below */
  dicom_cmd_text(cmd, &coff, 0x0002, "1.2.840.10008.1.1");
  dicom_cmd_us(cmd, &coff, 0x0100, DICOM_DIMSE_C_ECHO_RQ);
  dicom_cmd_us(cmd, &coff, 0x0110, 1);
  dicom_cmd_us(cmd, &coff, 0x0800, 0x0101);
  put_u32_le(cmd + 8, coff - 12);

  uint32_t pdv_len = coff + 2;
  uint32_t pdu_len = 4 + pdv_len;
  wire[0] = DICOM_PDU_P_DATA_TF;
  wire[1] = 0;
  put_u32_be(wire + 2, pdu_len);
  put_u32_be(wire + 6, pdv_len);
  wire[10] = 1;
  wire[11] = DICOM_PDV_FLAG_COMMAND | DICOM_PDV_FLAG_LAST_FRAGMENT;
  memcpy(wire + 12, cmd, coff);
  return 12 + coff;
}

static int test_dicom_pdu(const char *name, const uint8_t *wire, uint32_t wire_len,
                          dicom_packet_type_t expected_type) {
  dicom_packet_t *pkts = (dicom_packet_t *)calloc(4, sizeof(*pkts));
  uint8_t *out = (uint8_t *)malloc(131072);
  CHECK(pkts && out, "DICOM %s allocation failed", name);
  size_t n = parse_dicom_msg(wire, wire_len, pkts, 4);
  if (!(n == 1 && pkts[0].type == expected_type)) {
    fprintf(stderr, "[FAIL] DICOM %s expected type %d got count=%zu type=%d\n",
            name, expected_type, n, n ? pkts[0].type : -1);
    failures++;
    free(out);
    free(pkts);
    return 0;
  }
  dispatch_dicom_multiple_mutations(pkts, (int)n, 1);
  fix_dicom(pkts, (int)n);
  uint32_t out_len = 131072;
  if (!(reassemble_dicom_msgs(pkts, (uint32_t)n, out, &out_len) == 0 && out_len > 0)) {
    fprintf(stderr, "[FAIL] DICOM %s reassemble failed\n", name);
    failures++;
    free(out);
    free(pkts);
    return 0;
  }
  memset(pkts, 0, 4 * sizeof(*pkts));
  n = parse_dicom_msg(out, out_len, pkts, 4);
  if (!(n == 1)) {
    fprintf(stderr, "[FAIL] DICOM %s roundtrip parse failed\n", name);
    failures++;
    free(out);
    free(pkts);
    return 0;
  }
  free(out);
  free(pkts);
  return 1;
}

static int test_dicom(void) {
  uint8_t wire[512];
  uint32_t len;
  len = dicom_assoc_rq(wire);
  if (!test_dicom_pdu("A_ASSOCIATE_RQ", wire, len, DICOM_PKT_A_ASSOCIATE_RQ)) return 0;
  len = dicom_assoc_fixed(DICOM_PDU_A_ASSOCIATE_AC, wire);
  if (!test_dicom_pdu("A_ASSOCIATE_AC", wire, len, DICOM_PKT_A_ASSOCIATE_AC)) return 0;
  len = dicom_fixed4(DICOM_PDU_A_ASSOCIATE_RJ, 0, 1, 1, 1, wire);
  if (!test_dicom_pdu("A_ASSOCIATE_RJ", wire, len, DICOM_PKT_A_ASSOCIATE_RJ)) return 0;
  wire[0] = DICOM_PDU_P_DATA_TF; wire[1] = 0; put_u32_be(wire + 2, 0); len = 6;
  if (!test_dicom_pdu("P_DATA_TF", wire, len, DICOM_PKT_P_DATA_TF)) return 0;
  len = dicom_p_data_echo_command(wire);
  dicom_packet_t *pkts = (dicom_packet_t *)calloc(4, sizeof(*pkts));
  CHECK(pkts != NULL, "DICOM DIMSE allocation failed");
  size_t n = parse_dicom_msg(wire, len, pkts, 4);
  CHECK(n == 1 && pkts[0].type == DICOM_PKT_P_DATA_TF, "DICOM DIMSE P-DATA parse failed");
  CHECK(pkts[0].u.p_data_tf.pdv_count == 1 &&
        pkts[0].u.p_data_tf.pdvs[0].has_dimse_command &&
        pkts[0].u.p_data_tf.pdvs[0].dimse_command_field == DICOM_DIMSE_C_ECHO_RQ,
        "DICOM DIMSE command field parse failed");
  free(pkts);
  if (!test_dicom_pdu("P_DATA_TF_DIMSE_ECHO", wire, len, DICOM_PKT_P_DATA_TF)) return 0;
  len = dicom_fixed4(DICOM_PDU_A_RELEASE_RQ, 0, 0, 0, 0, wire);
  if (!test_dicom_pdu("A_RELEASE_RQ", wire, len, DICOM_PKT_A_RELEASE_RQ)) return 0;
  len = dicom_fixed4(DICOM_PDU_A_RELEASE_RP, 0, 0, 0, 0, wire);
  if (!test_dicom_pdu("A_RELEASE_RP", wire, len, DICOM_PKT_A_RELEASE_RP)) return 0;
  len = dicom_fixed4(DICOM_PDU_A_ABORT, 0, 0, 2, 0, wire);
  if (!test_dicom_pdu("A_ABORT", wire, len, DICOM_PKT_A_ABORT)) return 0;
  wire[0] = 0x99; wire[1] = 0; put_u32_be(wire + 2, 0); len = 6;
  if (!test_dicom_pdu("UNKNOWN", wire, len, DICOM_PKT_UNKNOWN)) return 0;
  return 1;
}

int main(void) {
  int ok = 1;
  ok &= test_dns();
  ok &= test_ssh();
  ok &= test_tls();
  ok &= test_dicom();
  if (!ok || failures) {
    fprintf(stderr, "message_type_coverage failed failures=%d\n", failures);
    return 1;
  }
  puts("message_type_coverage: PASS");
  return 0;
}
