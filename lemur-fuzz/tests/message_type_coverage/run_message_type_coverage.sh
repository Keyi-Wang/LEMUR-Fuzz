#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
mkdir -p "$BUILD_DIR"
CC="${CC:-clang}"
CFLAGS="${CFLAGS:--O2 -g -Wall -Wextra -Wno-unused-function}"
"$CC" $CFLAGS \
  -I"$ROOT_DIR/llm/dns" -I"$ROOT_DIR/llm/ssh" -I"$ROOT_DIR/llm/tls" -I"$ROOT_DIR/llm/dicom" \
  -o "$BUILD_DIR/message_type_coverage" \
  "$SCRIPT_DIR/message_type_coverage.c" \
  "$ROOT_DIR/llm/dns/dns_parser.c" "$ROOT_DIR/llm/dns/dns_reassembler.c" "$ROOT_DIR/llm/dns/dns_fixers.c" "$ROOT_DIR/llm/dns/dns_mutators.c" \
  "$ROOT_DIR/llm/ssh/ssh_parser.c" "$ROOT_DIR/llm/ssh/ssh_reassembler.c" "$ROOT_DIR/llm/ssh/ssh_fixers.c" "$ROOT_DIR/llm/ssh/ssh_mutators.c" \
  "$ROOT_DIR/llm/tls/tls_parser.c" "$ROOT_DIR/llm/tls/tls_reassembler.c" "$ROOT_DIR/llm/tls/tls_fixers.c" "$ROOT_DIR/llm/tls/tls_mutators.c" \
  "$ROOT_DIR/llm/dicom/dicom_parser.c" "$ROOT_DIR/llm/dicom/dicom_reassembler.c" "$ROOT_DIR/llm/dicom/dicom_fixers.c" "$ROOT_DIR/llm/dicom/dicom_mutators.c"
"$BUILD_DIR/message_type_coverage"
