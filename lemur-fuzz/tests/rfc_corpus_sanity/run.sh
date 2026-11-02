#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
BUILD=tests/rfc_corpus_sanity/build
mkdir -p "$BUILD"
python3 tests/rfc_corpus_sanity/generate_corpus.py
flags=(-std=c11 -g -O0 -fPIC -shared -I. -Wall -Wextra)
if [[ ${SANITIZE:-0} == 1 ]]; then flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer); fi
${CC:-gcc} "${flags[@]}" tests/rfc_corpus_sanity/bridge.c \
  llm/{dns/dns,ssh/ssh,tls/tls,dicom/dicom}_{parser,reassembler}.c \
  -o "$BUILD/bridge.so"
if [[ ${SANITIZE:-0} == 1 ]]; then
  ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=16 LD_PRELOAD="$(${CC:-gcc} -print-file-name=libasan.so)" \
    python3 tests/rfc_corpus_sanity/run_corpus.py --library "$BUILD/bridge.so" --report "${REPORT:-tests/rfc_corpus_sanity/report.json}"
else
  python3 tests/rfc_corpus_sanity/run_corpus.py --library "$BUILD/bridge.so" --report "${REPORT:-tests/rfc_corpus_sanity/report.json}"
fi
# Inspect decoded fields and borrowed-pointer lifetimes independently of MR.
exe_flags=()
for flag in "${flags[@]}"; do
  if [[ "$flag" != -shared ]]; then exe_flags+=("$flag"); fi
done
${CC:-gcc} "${exe_flags[@]}" tests/rfc_corpus_sanity/invariants.c \
  llm/{dns/dns,ssh/ssh,tls/tls,dicom/dicom}_{parser,reassembler}.c \
  llm/ssh/ssh_fixers.c -o "$BUILD/invariants"
"$BUILD/invariants"
