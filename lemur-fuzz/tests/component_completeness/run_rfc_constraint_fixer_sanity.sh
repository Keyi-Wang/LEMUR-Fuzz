#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build_fixer_sanity"
mkdir -p "$BUILD_DIR"
CC="${CC:-clang}"
CFLAGS="${CFLAGS:--O2 -g -Wall -Wextra -Wno-unused-function}"
"$CC" $CFLAGS \
  -I"$ROOT_DIR/llm/dns" -I"$ROOT_DIR/llm/ssh" -I"$ROOT_DIR/llm/tls" -I"$ROOT_DIR/llm/dicom" \
  -o "$BUILD_DIR/rfc_constraint_fixer_sanity" \
  "$SCRIPT_DIR/rfc_constraint_fixer_sanity.c" \
  "$ROOT_DIR/llm/dns/dns_fixers.c" \
  "$ROOT_DIR/llm/ssh/ssh_parser.c" \
  "$ROOT_DIR/llm/ssh/ssh_fixers.c" \
  "$ROOT_DIR/llm/ssh/ssh_reassembler.c" \
  "$ROOT_DIR/llm/tls/tls_fixers.c" \
  "$ROOT_DIR/llm/dicom/dicom_fixers.c"
"$BUILD_DIR/rfc_constraint_fixer_sanity"
