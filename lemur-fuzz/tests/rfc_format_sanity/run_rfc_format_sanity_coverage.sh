#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD="$ROOT/tests/rfc_format_sanity/build_coverage"
mkdir -p "$BUILD"
cd "$ROOT"
python3 - <<'PY'
from pathlib import Path
import shutil
b=Path('tests/rfc_format_sanity/build_coverage')
if b.exists():
    shutil.rmtree(b)
b.mkdir(parents=True)
PY
cc=${CC:-gcc}
COMMON="-std=c11 -Wall -Wextra -Wno-unused-parameter -I. -O0 -g --coverage -fprofile-arcs -ftest-coverage"
objs=""
for src in \
  llm/dns/dns_parser.c llm/dns/dns_fixers.c llm/dns/dns_reassembler.c llm/dns/dns_packets.c \
  llm/ssh/ssh_parser.c llm/ssh/ssh_fixers.c llm/ssh/ssh_reassembler.c llm/ssh/ssh_packets.c \
  llm/tls/tls_parser.c llm/tls/tls_fixers.c llm/tls/tls_reassembler.c llm/tls/tls_packets.c \
  llm/dicom/dicom_parser.c llm/dicom/dicom_fixers.c llm/dicom/dicom_reassembler.c llm/dicom/dicom_packets.c \
  tests/rfc_format_sanity/rfc_format_sanity.c; do
  obj="$BUILD/${src//\//__}.o"
  mkdir -p "$(dirname "$obj")"
  $cc $COMMON -c "$src" -o "$obj"
  objs="$objs $obj"
done
$cc --coverage $objs -o "$BUILD/rfc_format_sanity_cov"
"$BUILD/rfc_format_sanity_cov"
python3 - <<'PY'
from pathlib import Path
import subprocess, csv, sys, re
build=Path('tests/rfc_format_sanity/build_coverage')
targets=[
 'llm/dns/dns_parser.c','llm/dns/dns_reassembler.c',
 'llm/ssh/ssh_parser.c','llm/ssh/ssh_reassembler.c',
 'llm/tls/tls_parser.c','llm/tls/tls_reassembler.c',
 'llm/dicom/dicom_parser.c','llm/dicom/dicom_reassembler.c',
]
rows=[]
for src in targets:
    obj=build/(src.replace('/','__')+'.o')
    if not obj.exists():
        rows.append((src,'missing','','',''))
        continue
    for old_gcov in Path('.').glob('*.gcov'):
        old_gcov.unlink()
    subprocess.run(['gcov','-b','-c',str(obj)], cwd=Path('.'), check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gcov_path=Path(Path(src).name + '.gcov')
    if not gcov_path.exists():
        rows.append((src,'gcov_missing','','',''))
        continue
    lines=covered=0
    missing=[]
    for line in gcov_path.read_text(errors='replace').splitlines():
        parts=line.split(':',2)
        if len(parts)<3: continue
        cnt, lineno_s, code=parts
        cnt=cnt.strip(); lineno_s=lineno_s.strip()
        if not lineno_s.isdigit(): continue
        lineno=int(lineno_s)
        if cnt == '-': continue
        if 'GCOV_UNREACHABLE' in code or 'GCOV_EXCL_LINE' in code:
            continue
        lines += 1
        if cnt not in ('#####','=====', '0'):
            covered += 1
        else:
            stripped=code.strip()
            if stripped and not stripped.startswith('//'):
                missing.append(lineno)
    pct=100.0*covered/lines if lines else 0.0
    rows.append((src,f'{pct:.2f}',covered,lines,missing[:120]))
out=build/'parser_reassembler_line_coverage.csv'
with out.open('w', newline='') as f:
    w=csv.writer(f); w.writerow(['source','line_pct','covered','lines','missing_lines_prefix']); w.writerows(rows)
print(out)
for r in rows:
    print(r)
PY
