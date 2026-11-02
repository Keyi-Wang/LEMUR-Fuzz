#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
cc=${CC:-gcc}
$cc -std=c11 -Wall -Wextra -Wno-unused-parameter -I. \
  tests/rfc_format_sanity/rfc_format_sanity.c \
  llm/dns/dns_parser.c llm/dns/dns_fixers.c llm/dns/dns_reassembler.c llm/dns/dns_packets.c \
  llm/ssh/ssh_parser.c llm/ssh/ssh_fixers.c llm/ssh/ssh_reassembler.c llm/ssh/ssh_packets.c \
  llm/tls/tls_parser.c llm/tls/tls_fixers.c llm/tls/tls_reassembler.c llm/tls/tls_packets.c \
  llm/dicom/dicom_parser.c llm/dicom/dicom_fixers.c llm/dicom/dicom_reassembler.c llm/dicom/dicom_packets.c \
  -o tests/rfc_format_sanity/rfc_format_sanity
./tests/rfc_format_sanity/rfc_format_sanity
