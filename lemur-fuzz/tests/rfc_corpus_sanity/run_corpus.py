#!/usr/bin/env python3
"""Strict round-trip gate; report all failures, never xfail known defects."""
import argparse
import ctypes as C
import json
from pathlib import Path
from collections import Counter

ap=argparse.ArgumentParser()
ap.add_argument('--library',type=Path,required=True)
ap.add_argument('--corpus',type=Path,default=Path(__file__).parent/'corpus')
ap.add_argument('--report',type=Path,default=Path(__file__).parent/'report.json')
args=ap.parse_args()
lib=C.CDLL(str(args.library.resolve()))
manifest=json.loads((args.corpus/'manifest.json').read_text())
summary={};failures=[];capability_gaps=[]
for proto in ['dns','ssh','tls','dicom']:
    fn=getattr(lib,'roundtrip_'+proto)
    fn.argtypes=[C.c_void_p,C.c_uint32,C.c_void_p,C.POINTER(C.c_uint32),C.c_int,C.POINTER(C.c_uint32)]
    fn.restype=C.c_int
    counts=Counter()
    probe=getattr(lib,'gaps_'+proto)
    probe.argtypes=[C.c_void_p,C.c_uint32];probe.restype=C.c_uint
    gap_labels={1:'unclassified_message',2:'opaque_fields',4:'capacity_fallback',8:'fragment_not_decoded',16:'following_handshakes_not_decoded'}
    def run(wire,structural):
        inp=C.create_string_buffer(wire)
        out=C.create_string_buffer(max(262144,len(wire)*2))
        cap=C.c_uint32(len(out));n=C.c_uint32()
        rc=fn(inp,len(wire),out,C.byref(cap),structural,C.byref(n))
        return rc,n.value,out.raw[:cap.value] if rc==0 else b''
    for row in (r for r in manifest if r['protocol']==proto):
        wire=(args.corpus/row['path']).read_bytes()
        if row['kind']=='safety':
            run(wire,0);run(wire,1);counts['safety_executed']+=1;continue
        counts['positive']+=1
        mask=probe(C.create_string_buffer(wire),len(wire))
        if mask:
            counts['field_model_gap_seeds']+=1
            capability_gaps.append(dict(protocol=proto,name=row['name'],path=row['path'],gaps=[name for bit,name in gap_labels.items() if mask&bit]))
        for structural in [0,1]:
            mode='structured' if structural else 'wire'
            rc,n,out=run(wire,structural)
            if rc==0 and n==row['packets'] and out==wire:
                counts[mode+'_pass']+=1
            else:
                reason='parse_rejected' if rc==-11 else 'reassembly_error' if rc else 'packet_count' if n!=row['packets'] else 'byte_mismatch'
                diff=next((i for i,(a,b) in enumerate(zip(wire,out)) if a!=b),min(len(wire),len(out)))
                counts[mode+'_fail']+=1
                failures.append(dict(protocol=proto,name=row['name'],path=row['path'],source=row['source'],dimension=row['dimension'],mode=mode,reason=reason,rc=rc,packet_count=n,input_len=len(wire),output_len=len(out),first_diff=diff))
            if rc==0:
                rc2,n2,out2=run(out,structural)
                if rc2 or n2!=n or out2!=out:
                    counts[mode+'_fixed_point_fail']+=1
    summary[proto]=dict(counts)
    print(proto,dict(counts),flush=True)
args.report.parent.mkdir(parents=True,exist_ok=True)
args.report.write_text(json.dumps(dict(summary=summary,failures=failures,capability_gaps=capability_gaps),indent=2)+'\n')
raise SystemExit(1 if failures or any(v for counts in summary.values() for k,v in counts.items() if k.endswith("fixed_point_fail")) else 0)
