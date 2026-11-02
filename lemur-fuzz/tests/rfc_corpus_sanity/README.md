# DICOM / DNS / SSH / TLS round-trip regression

Run from the repository root:

```sh
bash tests/rfc_corpus_sanity/run.sh
SANITIZE=1 REPORT=tests/rfc_corpus_sanity/report-sanitized.json bash tests/rfc_corpus_sanity/run.sh
bash tests/rfc_format_sanity/run_rfc_format_sanity.sh
```

The independent Python encoders generate 1,901 positive format fixtures:
DNS 176, SSH 213, TLS 424, DICOM 1,088. Each fixture must satisfy byte-for-byte
`R(P(M)) == M`, the expected packet count, and a second-round fixed point.
Another 324 truncated/malformed inputs exercise memory safety; they are not
claimed to be legal messages. Cryptographic fixture bytes are not authenticated
sessions or valid certificates.

Two distinct paths are tested. `wire` permits the original packet cache;
`structured` clears that cache for **all four protocols**. Previously DNS,
SSH and TLS ignored this switch. Structured mode still retains opaque payload
fields and overflow slices: it tests reconstruction of the packet model, not
complete semantic decoding of every byte. Capability gaps are reported separately
and are never erased by a successful round trip. `invariants.c` additionally
checks field edits, bounded output, oversized-field rejection, DICOM related UID
semantics and the lifetime of TLS coalesced-handshake pointers.

Changes in this pass:

- DNS: preserve up to 65,535 wire bytes; retain excess section records, RDATA and
  DSO TLVs as bounded borrowed slices; preserve a complete EDNS option vector
  when the editable option array fills. Check borrowed RDATA lengths before
  serialization. Preserve compression encodings and OPT placement.
- SSH: fall back to complete transport payloads when mpint/name/string templates
  cannot represent the input; preserve oversized opaque stream tails and received
  boolean octets. Never mark a truncated field projection as complete.
- TLS: retain fragmented/coalesced/encrypted alerts and unknown record payloads;
  use the opaque handshake body when certificate/typed-body arrays are too small;
  track continuation records and avoid pointers into stack reconstruction buffers.
- DICOM: read/write the common extended negotiation related-UID vector length;
  preserve oversized PDVs and excess PDV items; retain large PDU cache tails;
  invalidate an association cache when its negotiated fields change, and retain
  legal presentation context IDs above 127.
- All parsers reject a batch that cannot be fully consumed within `max_count`
  instead of returning success for a silently shortened prefix.

API requirements and limits:

- Borrowed fields point into the original input. Keep that buffer alive and
  unchanged until serialization completes, and use a separate output buffer.
  Copying a packet struct does not copy the borrowed bytes. TLS/SSH already used
  this convention; DNS/DICOM now also use it for oversized payloads.
- Set `max_count` and output capacity for the entire input. A zero parse result or
  nonzero serialization result is an error; do not treat partial output as a
  complete message. Packet caches must be invalidated when editing fields.
- DNS inputs use the existing unprefixed-message API. DNS-over-TCP length prefixes
  and transport/session state are outside this API. In particular DSO needs an
  externally delimited message; concatenated unframed DSO messages are ambiguous.
- This is a bounded editable model with lossless opaque preservation, not an
  unbounded semantic model. Excess DNS records/large SSH fields/TLS certificates/
  DICOM PDVs may not have individual editable fields. Arbitrary DICOM extension
  ordering and unknown negotiation items can require the whole-PDU cache.
- Round-trip correctness does not prove RFC validity or cryptographic validity.
  Encrypted SSH/TLS contents cannot be decoded without session keys/state. These
  tests are regression evidence, not a proof over every legal message.

Specifications used for layout checks:
[DICOM common extended negotiation](https://dicom.nema.org/medical/dicom/current/output/chtml/part07/sect_D.3.3.6.html),
[SSH wire data types, RFC 4251 §5](https://www.rfc-editor.org/rfc/rfc4251.html#section-5),
[TLS 1.2 record fragmentation, RFC 5246 §6.2.1](https://www.rfc-editor.org/rfc/rfc5246.html#section-6.2.1).
TLS 1.3 alert restrictions differ from TLS 1.2; the permissive record parser is
not a TLS version/state validator.

Additional smoke validation used `ROUNDS=3 MAX_PKTS=16` against existing seed
sets: DNS 72, SSH 80, TLS 36, DICOM 82 mutators. DNS `mutate_wire` intentionally
corrupts raw bytes and failed the legal-format check when included; it was
excluded from that specific structural-mutator smoke run, not from MR testing.
