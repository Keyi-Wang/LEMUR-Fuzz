#!/usr/bin/env python3
"""Combine the legacy sanity and independent RFC corpus; enforce line coverage.
Raw and reviewed-exclusion totals are both reported. Failing wire cases remain
failures even when they contribute executable-line coverage.
"""
import csv
import gzip
import json
import os
import subprocess as sp
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
os.chdir(ROOT)
BUILD=ROOT/'tests/rfc_corpus_sanity/build_coverage'
BUILD.mkdir(parents=True,exist_ok=True)
for p in BUILD.glob('*.gcda'):p.unlink()
cc=os.environ.get('CC','gcc')
objects=[];targets=[]
for proto in ['dns','ssh','tls','dicom']:
    for part in ['parser','reassembler','fixers','packets']:
        src=f'llm/{proto}/{proto}_{part}.c'
        obj=BUILD/(src.replace('/','__')+'.o')
        sp.run([cc,'-std=c11','-O0','-g','-fPIC','--coverage','-I.','-c',src,'-o',str(obj)],check=True)
        objects.append(obj)
        if part in ['parser','reassembler']:targets.append((src,obj))
legacy=BUILD/'legacy'
sp.run([cc,'-std=c11','-O0','-g','--coverage','-I.','tests/rfc_format_sanity/rfc_format_sanity.c',*map(str,objects),'-o',str(legacy)],check=True)
with (BUILD/'legacy.log').open('w') as log:legacy_rc=sp.run([str(legacy)],stdout=log,stderr=sp.STDOUT).returncode
lib=BUILD/'bridge.so'
sp.run([cc,'-std=c11','-O0','-g','-fPIC','-shared','--coverage','-I.','tests/rfc_corpus_sanity/bridge.c',*map(str,objects),'-o',str(lib)],check=True)
with (BUILD/'corpus.log').open('w') as log:
    corpus_rc=sp.run(['python3','tests/rfc_corpus_sanity/run_corpus.py','--library',str(lib),'--report',str(BUILD/'corpus.json')],stdout=log,stderr=sp.STDOUT).returncode
results=[]
for src,obj in targets:
    sp.run(['gcov','-j',str(obj)],cwd=BUILD,stdout=sp.DEVNULL,check=True)
    report=json.loads(gzip.decompress((BUILD/(obj.stem+'.gcov.json.gz')).read_bytes()))
    f=next(f for f in report['files'] if f['file'].endswith(src))
    source=(ROOT/src).read_text().splitlines()
    raw=f['lines']
    excluded=[x for x in raw if 'GCOV_UNREACHABLE' in source[x['line_number']-1] or 'GCOV_EXCL_LINE' in source[x['line_number']-1]]
    included=[x for x in raw if x not in excluded]
    missing=[x['line_number'] for x in included if not x['count']]
    row=dict(source=src,covered=sum(x['count']>0 for x in included),lines=len(included),line_pct=round(100*(len(included)-len(missing))/len(included),2),missing=missing,raw_covered=sum(x['count']>0 for x in raw),raw_lines=len(raw),excluded=[x['line_number'] for x in excluded])
    results.append(row);print(row,flush=True)
result=dict(legacy_exit=legacy_rc,corpus_exit=corpus_rc,coverage=results)
(BUILD/'coverage.json').write_text(json.dumps(result,indent=2)+'\n')
print('Legacy sanity exit:',legacy_rc,'Strict corpus exit:',corpus_rc)
raise SystemExit(1 if legacy_rc or corpus_rc or any(r['missing'] for r in results) else 0)
