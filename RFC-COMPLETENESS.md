# Lemur-Fuzz RFC/spec completeness checkpoint

This checkpoint uses RFC/protocol specifications as the message universe, not ProFuzzBench seeds.  The executable checker is:

```bash
cd /home/keyi/icse-rebuttal/lemur-fuzz/lemur-fuzz
./tests/component_completeness/check_component_completeness.py
```

Last validated on 2026-09-25 in `/home/keyi/icse-rebuttal/lemur-fuzz/lemur-fuzz`.

## Specification sources

- DNS: RFC 1034, RFC 1035, RFC 1996, RFC 2136, RFC 6891 under `components-generation/rfc/`.
- SSH: RFC 4251, RFC 4252, RFC 4253, RFC 4254 under `components-generation/rfc/`.
- TLS: RFC 5246 and RFC 6066 under `components-generation/rfc/`; the component keeps additional TLS 1.3/DTLS enum values as generic handshake alternatives while the modeled request path remains TLS-record/ClientHello oriented.
- DICOM: PS3.8 network PDU and PS3.7 DIMSE command-set material under `components-generation/rfc/`.

## Message-template and field coverage

- DNS covers QUERY, IQUERY, STATUS, NOTIFY, UPDATE, and EDNS OPT. Templates include header flags/counts, question QNAME/QTYPE/QCLASS, RR NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA, additional section, and decoded OPT fields.
- SSH covers RFC 4253 transport/key-exchange/service messages, RFC 4252 user-auth messages, and RFC 4254 global/channel messages. Dedicated templates handle banner, binary transport packet, KEXINIT, KEXDH_INIT, SERVICE_REQUEST, and NEWKEYS. The remaining RFC message bodies use `ssh_typed_payload_t` with schema, boolean, uint32, SSH string, and trailing payload fields. RFC 4252 `USERAUTH_REQUEST` now parses and reassembles the method-specific `publickey`, `password`, and `hostbased` request fields, and message 60 is represented as `SSH_MSG_USERAUTH_PK_OK`/`SSH_MSG_USERAUTH_METHOD_REPLY`.
- TLS covers change_cipher_spec, alert, handshake, application_data, and the client request handshake messages needed by a TLS server: ClientHello plus generic Certificate, ClientKeyExchange, CertificateVerify, and Finished. ClientHello has structured version/random/session-id/cipher-suite/compression/extension fields.
- DICOM covers PS3.8 A-ASSOCIATE-RQ/AC/RJ, P-DATA-TF, A-RELEASE-RQ/RP, A-ABORT, UNKNOWN passthrough, explicit A-ASSOCIATE-RQ User Information sub-items 0x51 Maximum Length, 0x52 Implementation Class UID, 0x53 Asynchronous Operations Window, 0x54 SCU/SCP Role Selection, 0x55 Implementation Version Name, private/unknown user-info sub-items, plus PS3.7 request DIMSE commands for C-STORE, C-GET, C-FIND, C-MOVE, C-ECHO, C-CANCEL, N-EVENT-REPORT, N-GET, N-SET, N-ACTION, N-CREATE, and N-DELETE.

## Mutator coverage

The checker verifies required field-level mutator entry points, including tag-driven optional/repeatable operations.

- DNS: 68 registered mutators.
- SSH: 80 registered mutators, including structured typed-payload field mutators.
- TLS: 35 registered mutators, including record length, ClientHello presence/body length, and uint24 handshake length byte mutators.
- DICOM: 82 registered mutators, including association items, presentation contexts, transfer syntaxes, explicit User Information sub-items, unknown/private user-info data, PDVs, DIMSE status/attribute-list fields, AC raw items, and UNKNOWN PDU passthrough fields.

## Format-constraint/fixer coverage

The checker now validates a constraint-to-fixer matrix rather than only checking for broad fixer files.

- DNS: 12 format constraints mapped to named fixers, including query header bits, opcode set, section count synchronization, label/name length, compression normalization, RDLENGTH/RDATA synchronization, UDP/AXFR behavior, NOTIFY SOA question, UPDATE Zone SOA question, and EDNS OPT shape/placement/flags.
- SSH: 7 format constraints mapped to named fixers, including identification string, binary packet length/padding/block alignment, KEXINIT name-lists/reserved field, KEXDH_INIT mpint, SERVICE_REQUEST name, NEWKEYS body, and typed message-body schema/string/boolean/uint32 constraints.
- TLS: 7 format constraints mapped to named fixers, including record length/version bounds, ChangeCipherSpec value, alert level/description enums, handshake type/uint24 length, ClientHello vector constraints, RFC6066 extension TLV shape, and application_data length bounds.
- DICOM: 9 format constraints mapped to named fixers, including PDU header lengths/reserved fields, A-ASSOCIATE-RQ required items and item lengths, explicit User Information sub-item shape/length constraints, A-ASSOCIATE-AC fixed fields/raw item bounds, A-ASSOCIATE-RJ enum constraints, P-DATA-TF PDV shape, A-RELEASE fixed bodies, A-ABORT source/reason, and PS3.7 DIMSE request command-set constraints.

## Validation results

Commands run successfully:

```bash
cd /home/keyi/icse-rebuttal/lemur-fuzz/lemur-fuzz
./tests/component_completeness/check_component_completeness.py
./tests/component_completeness/run_rfc_constraint_fixer_sanity.sh
make -j2
./tests/rfc_format_sanity/run_rfc_format_sanity.sh
./tests/rfc_format_sanity/run_rfc_format_sanity_coverage.sh
./tests/message_type_coverage/run_message_type_coverage.sh
for proto in dns ssh tls dicom; do ROUNDS=2 ./tests/mutator_sanity/run_mutator_sanity.sh "$proto" ../components-generation/tests/seeds/$proto; done
```

Parser/reassembler reachable-line coverage from `tests/rfc_format_sanity/build_coverage/parser_reassembler_line_coverage.csv`:

| Source | Line coverage |
|---|---:|
| `llm/dns/dns_parser.c` | 100.00% |
| `llm/dns/dns_reassembler.c` | 100.00% |
| `llm/ssh/ssh_parser.c` | 100.00% |
| `llm/ssh/ssh_reassembler.c` | 100.00% |
| `llm/tls/tls_parser.c` | 100.00% |
| `llm/tls/tls_reassembler.c` | 100.00% |
| `llm/dicom/dicom_parser.c` | 100.00% |
| `llm/dicom/dicom_reassembler.c` | 100.00% |

`tests/component_completeness/run_rfc_constraint_fixer_sanity.sh` verifies fixer behavior by constructing invalid DNS/SSH/TLS/DICOM packets and checking the corrected constraints.

`tests/message_type_coverage/run_message_type_coverage.sh` was also updated to allocate the large DICOM packet buffers on the heap, avoiding stack overflow in the test harness.

Latest mutator sanity counts: DNS 68, SSH 80, TLS 35, DICOM 82; all finished with `illegal=0`.
