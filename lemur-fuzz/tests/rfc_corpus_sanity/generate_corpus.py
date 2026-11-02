#!/usr/bin/env python3
"""Independent wire encoders: no Lemur parser/serializer or benchmark seeds.
Every seed records its normative source and the dimension varied. Cryptographic
values are format fixtures, not valid signatures/certificates or session MACs.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

B16 = lambda x: struct.pack('!H', x)
B32 = lambda x: struct.pack('!I', x)
L16 = lambda x: struct.pack('<H', x)
L32 = lambda x: struct.pack('<I', x)
V8 = lambda x: bytes([len(x)]) + x
V16 = lambda x: B16(len(x)) + x
V24 = lambda x: len(x).to_bytes(3, 'big') + x
S = lambda x: B32(len(x)) + x
rows = []
root = None

def emit(proto, name, wire, source, dimension, *, kind='positive', packets=1):
    rel = f'{proto}/{name}.bin'
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wire)
    rows.append(dict(protocol=proto, name=name, path=rel, source=source,
                     dimension=dimension, kind=kind, packets=packets,
                     length=len(wire), sha256=hashlib.sha256(wire).hexdigest()))


def dns():
    src = 'RFC1035 §§3.2–3.4,4.1; RFC2136 §2; RFC1996 §3; RFC6891 §6'
    name = lambda labels: b''.join(V8(x) for x in labels) + b'\0'
    qname = name([b'example', b'org'])
    rr = lambda typ, data, cls=1, ttl=300, owner=b'\xc0\x0c': owner+B16(typ)+B16(cls)+B32(ttl)+V16(data)
    msg = lambda op, questions, answers=(), auth=(), additional=(): (B16(0x3a7b)+B16(op<<11)+B16(len(questions))+B16(len(answers))+B16(len(auth))+B16(len(additional))+b''.join(questions)+b''.join(answers)+b''.join(auth)+b''.join(additional))
    names = [b'\0', qname, name([b'A'*63]), name([b'a'*63]*3+[b'z'*61]), name([b'x']*127)]
    qtypes = list(range(1,17)) + [28,33,41,252,253,254,255]
    for ni, n in enumerate(names):
        for typ in qtypes:
            emit('dns',f'query-name{ni}-type{typ}',msg(0,[n+B16(typ)+B16(1)]),src,'QNAME boundary × QTYPE')
    for cls in [1,3,4,255]:
        emit('dns',f'query-class{cls}',msg(0,[qname+B16(1)+B16(cls)]),src,'QCLASS')
    # Historical RFC1035 IQUERY and STATUS are identified separately from current usage.
    emit('dns','iquery',msg(1,[],[rr(1,b'\x7f\0\0\1',owner=b'\0')]),src,'historical IQUERY')
    emit('dns','status',msg(2,[]),src,'historical STATUS')
    emit('dns','notify',msg(4,[qname+B16(6)+B16(1)]),src,'NOTIFY SOA')
    rdatas = {1:b'\xc0\0\x02\x01',2:qname,3:qname,4:qname,5:qname,
              6:qname+name([b'hostmaster',b'example',b'org'])+b''.join(B32(v) for v in [1,3600,600,86400,60]),
              7:qname,8:qname,9:qname,10:b'\x00\xff\x01',11:b'\xc0\0\x02\x01\x06\x80',
              12:qname,13:V8(b'CPU')+V8(b'OS'),14:qname+qname,15:B16(10)+qname,
              16:V8(b'')+V8(b'x'*255)+V8(b'last')}
    for typ,data in rdatas.items():
        emit('dns',f'update-rdata-{typ}',msg(5,[qname+B16(6)+B16(1)],auth=[rr(typ,data)]),src,'UPDATE typed RDATA')
    for cls,ttl,data,label in [(255,0,b'','delete-rrset'),(254,0,rdatas[1],'delete-rr'),(1,60,rdatas[1],'add')]:
        emit('dns',f'update-{label}',msg(5,[qname+B16(6)+B16(1)],auth=[rr(1,data,cls,ttl)]),src,'UPDATE class/TTL/RDATA semantics')
    for n in [1,2,31,32,33,64]:
        emit('dns',f'update-repeat-{n}',msg(5,[qname+B16(6)+B16(1)],auth=[rr(1,rdatas[1])]*n),src,'RR count boundary')
    for placement in range(3):
        for optdata in [b'',B16(65001)+V16(b''),B16(65001)+V16(b'xyz')+B16(65002)+V16(b'abc')]:
            opt=rr(41,optdata,1232,0x8000,b'\0')
            additional=[rr(1,rdatas[1]),rr(16,V8(b'z'))]
            additional.insert(placement,opt)
            emit('dns',f'edns-position{placement}-len{len(optdata)}',msg(0,[qname+B16(1)+B16(1)],additional=additional),src,'OPT placement and option list')
    for opcode,tlvs,label in [(6,b'','dso-header'),(6,B16(1)+V16(B32(60000)+B32(15000)),'dso-keepalive'),(6,B16(1)+V16(B32(60000)+B32(15000))+B16(3)+V16(bytes(16)),'dso-padding')]:
        emit('dns',label,msg(opcode,[])+tlvs,'RFC8490 §§5,7','DSO opcode and TLV request')
    emit('dns','ixfr',msg(0,[qname+B16(251)+B16(1)],auth=[rr(6,rdatas[6])]),'RFC1995 §3','IXFR serial in authority SOA')
    for n in [0,1,2048,2049,4096]:
        emit('dns',f'update-null-rdata-{n}',msg(5,[qname+B16(6)+B16(1)],auth=[rr(10,bytes(n))]),src,'RDLENGTH capacity boundary')


def ssh():
    src='RFC4251 §5; RFC4252 §§5–9; RFC4253 §§4,6,7,8,11; RFC4254 §§4–7'
    def packet(payload, pad_extra=0, salt=0):
        pad=8-((5+len(payload))%8)
        if pad<4: pad+=8
        pad+=pad_extra
        return B32(1+len(payload)+pad)+bytes([pad])+payload+bytes((i*31+salt)%256 for i in range(pad))
    bodies={
        'disconnect':b'\x01'+B32(11)+S(b'bye')+S(b'en'),
        'ignore':b'\x02'+S(b'\0\xff'), 'unimplemented':b'\x03'+B32(0xffffffff),
        'debug':b'\x04\x01'+S(b'debug')+S(b''),
        'service-request':b'\x05'+S(b'ssh-userauth'), 'newkeys':b'\x15',
        'kexdh-init':b'\x1e'+S(b'\0\x80'),
        'auth-none':b'\x32'+S(b'user')+S(b'ssh-connection')+S(b'none'),
        'window-adjust':b'\x5d'+B32(7)+B32(0xffffffff),
        'channel-eof':b'\x60'+B32(7), 'channel-close':b'\x61'+B32(7),
    }
    lists=[b'diffie-hellman-group14-sha1',b'ssh-rsa',b'aes128-ctr',b'aes128-ctr',b'hmac-sha1',b'hmac-sha1',b'none',b'none',b'',b'']
    bodies['kexinit']=b'\x14'+bytes(range(16))+b''.join(S(x) for x in lists)+b'\0'+B32(0)
    for flag in [0,1]:
        head=b'\x32'+S(b'user')+S(b'ssh-connection')
        bodies[f'auth-publickey-{flag}']=head+S(b'publickey')+bytes([flag])+S(b'ssh-rsa')+S(S(b'ssh-rsa')+S(b'\x01\0\x01')+S(b'\0\x80'))+(S(S(b'ssh-rsa')+S(b'sig')) if flag else b'')
        bodies[f'auth-password-{flag}']=head+S(b'password')+bytes([flag])+S(b'old')+(S(b'new') if flag else b'')
    bodies['auth-hostbased']=head+S(b'hostbased')+S(b'ssh-rsa')+S(b'key')+S(b'host.')+S(b'localuser')+S(b'sig')
    for req in [b'tcpip-forward',b'cancel-tcpip-forward']:
        for flag in [0,1]:
            bodies[f'global-{req.decode()}-{flag}']=b'\x50'+S(req)+bytes([flag])+S(b'127.0.0.1')+B32(2222)
    for channel in [b'session',b'x11',b'direct-tcpip',b'forwarded-tcpip']:
        tail=b''
        if channel!=b'session':
            tail=(S(b'dest')+B32(22) if channel!=b'x11' else b'')+S(b'127.0.0.1')+B32(49152)
        bodies[f'open-{channel.decode()}']=b'\x5a'+S(channel)+B32(7)+B32(2097152)+B32(32768)+tail
    tails={b'pty-req':S(b'xterm')+b''.join(B32(x) for x in [80,24,0,0])+S(b'\x01'+B32(3)+b'\0'),
           b'x11-req':b'\x01'+S(b'MIT-MAGIC-COOKIE-1')+S(b'00ff')+B32(0),
           b'env':S(b'LANG')+S(b'C'),b'shell':b'',b'exec':S(b'echo test'),b'subsystem':S(b'sftp'),
           b'window-change':b''.join(B32(x) for x in [120,40,800,600]),b'xon-xoff':b'\x01',
           b'signal':S(b'TERM'),b'exit-status':B32(0),b'exit-signal':S(b'TERM')+b'\0'+S(b'')+S(b'en')}
    for req,tail in tails.items():
        for flag in [0,1]: bodies[f'request-{req.decode()}-{flag}']=b'\x62'+B32(7)+S(req)+bytes([flag])+tail
    for n in [0,1,4095,4096,4097,8192,32768]:
        bodies[f'channel-data-{n}']=b'\x5e'+B32(7)+S(b'x'*n)
        bodies[f'extended-data-{n}']=b'\x5f'+B32(7)+B32(1)+S(b'x'*n)
    bodies['auth-keyboard-interactive']=b'\x32'+S(b'user')+S(b'ssh-connection')+S(b'keyboard-interactive')+S(b'en')+S(b'')
    for n in [0,1,2,8,9]: bodies[f'auth-info-response-{n}']=b'\x3d'+B32(n)+b''.join(S(b'response') for _ in range(n))
    bodies['kex-dh-gex-request']=b'\x22'+B32(1024)+B32(2048)+B32(8192)
    bodies['kex-dh-gex-init']=b'\x20'+S(b'\0\x80')
    for label,payload in bodies.items():
        for extra in [0,8,32]:
            wire=packet(payload,extra,17)
            emit('ssh',f'{label}-pad{extra}',wire,src+'; RFC4256 §3.4; RFC4419 §3','message/body subtype × nonzero padding')
    for comment in [b'',b' comment with spaces']:
        emit('ssh',f'banner-{len(comment)}',b'SSH-2.0-LemurTest'+comment+b'\r\n',src,'identification comment')
    emit('ssh','client-sequence',b'SSH-2.0-LemurTest\r\n'+b''.join(packet(bodies[k],salt=67) for k in ['kexinit','kexdh-init','newkeys']),src,'concatenated transport sequence',packets=4)


def tls():
    src='RFC5246 §§6.2.1,7.4; RFC6066 §§3–9; RFC8446 §§4,5'
    record=lambda data,typ=22: bytes([typ,3,3])+V16(data)
    hs=lambda typ,data: bytes([typ])+V24(data)
    ext=lambda typ,data: B16(typ)+V16(data)
    extensions=[b'',ext(0,V16(b'\0'+V16(b'example.org'))),ext(1,b'\x01'),ext(2,V16(b'\0')),ext(3,b''),ext(4,b''),ext(5,b'\x01'+V16(b'')+V16(b'')),ext(13,V16(b'\x04\x01\x05\x03')),ext(43,V8(b'\x03\x04\x03\x03')),ext(10,V16(b'\0\x1d\0\x17')),ext(51,V16(B16(29)+V16(bytes(range(32)))))]
    hellos=[]
    for sidlen in [0,1,31,32]:
        for csn in [1,2,255,256,257]:
            for ei,extension in enumerate([None]+extensions):
                body=b'\x03\x03'+bytes(range(32))+V8(bytes(sidlen))+V16(b'\x00\x2f'*csn)+V8(b'\0')
                if extension is not None: body+=V16(extension)
                wire=hs(1,body)
                emit('tls',f'hello-sid{sidlen}-cs{csn}-ext{ei}',record(wire),src,'ClientHello vector boundaries and extension families')
                if sidlen==0 and csn==1: hellos.append(wire)
    messages=[('certificate-empty',hs(11,V24(b''))),('certificate-chain',hs(11,V24(V24(b'\x30\x00')+V24(b'\x30\x02\x01\x00')))),
              ('client-key-rsa',hs(16,V16(bytes(range(128))))),('client-key-dh',hs(16,V16(b'\x01\x80'))),('client-key-implicit-dh',hs(16,b'')),
              ('certificate-verify',hs(15,b'\x04\x01'+V16(bytes(64)))),('finished12',hs(20,bytes(range(12)))),
              ('certificate13-empty',hs(11,V8(b'context')+V24(b''))),('certificate-verify13',hs(15,B16(0x0804)+V16(bytes(64)))),
              ('finished13',hs(20,bytes(range(32)))),('end-of-early-data',hs(5,b'')),('key-update0',hs(24,b'\0')),('key-update1',hs(24,b'\1')),
              ('certificate-url',hs(21,b'\0'+V16(V16(b'https://example.org/cert')+b'\x01'+bytes(20))))]
    for label,data in messages: emit('tls',label,record(data),src,'request handshake body (TLS1.3 decrypted-format fixture)')
    for i,data in enumerate(hellos[:3]):
        emit('tls',f'coalesced-{i}',record(data+messages[0][1]+messages[2][1]),src,'multiple handshakes in one record')
        for split in range(1,len(data)):
            emit('tls',f'fragment-{i}-{split}',record(data[:split])+record(data[split:]),src,'every handshake split point',packets=2)
    for typ,data in [(20,b'\1'),(21,b'\1\0'),(23,b''),(23,bytes(16384))]:
        emit('tls',f'record-{typ}-{len(data)}',record(data,typ),src,'record type boundary')


def dicom():
    src='DICOM PS3.7 §§9.3,10.3,D.3; PS3.8 §§9.3,Annex D'
    pdu=lambda typ,b: bytes([typ,0])+B32(len(b))+b
    item=lambda typ,b: bytes([typ,0])+V16(b)
    uid=b'1.2.840.10008.1.1'
    app=item(0x10,b'1.2.840.10008.3.1.1.1')
    pc=lambda n,ts: item(0x20,bytes([n,0,0,0])+item(0x30,uid)+b''.join(item(0x40,t) for t in ts))
    fixed=B16(1)+B16(0)+b'ANY-SCP         '+b'LEMR-SCU        '+bytes(32)
    mandatory=item(0x51,B32(16384))+item(0x52,b'1.2.3.4')
    extra=[item(0x53,B16(0)+B16(1)),item(0x54,V16(uid)+b'\1\1'),item(0x55,b'LEMR_TEST'),
           item(0x56,V16(uid)+b'\1\0'),item(0x57,V16(uid)+V16(b'1.2.840.10008.4.2')+V16(V16(uid))),
           item(0x58,b'\1\1'+V16(b'user')+V16(b'')),item(0x58,b'\2\0'+V16(b'user')+V16(b'password'))]
    for n in [1,2,8,16,17,127,128]:
        for ti,ts in enumerate([[b'1.2.840.10008.1.2'],[b'1.2.840.10008.1.2',b'1.2.840.10008.1.2.1']]):
            emit('dicom',f'assoc-pc{n}-ts{ti}',pdu(1,fixed+app+b''.join(pc(2*i+1,ts) for i in range(n))+item(0x50,mandatory)),src,'presentation contexts × transfer syntaxes')
    for i,e in enumerate(extra):
        emit('dicom',f'assoc-user-item-{i}',pdu(1,fixed+app+pc(1,[b'1.2.840.10008.1.2'])+item(0x50,mandatory+e)),src,'optional extended/common/user-identity negotiation')
    elem=lambda tag,b: L16(0)+L16(tag)+L32(len(b))+b
    ui=lambda b: b+(b'\0' if len(b)%2 else b'')
    pdv=lambda data,control=3,pcid=1: B32(len(data)+2)+bytes([pcid,control])+data
    cmds=[1,0x10,0x20,0x21,0x30,0xfff,0x100,0x110,0x120,0x130,0x140,0x150]
    for cmd in cmds:
        for mid in [0,1,65535]:
            fields={0x100:L16(cmd),0x800:L16(0x101 if cmd in [0x30,0xfff,0x110,0x150] else 0)}
            if cmd==0xfff: fields[0x120]=L16(mid)
            else:
                fields[0x110]=L16(mid)
                fields[0x3 if cmd in [0x110,0x120,0x130,0x150] else 0x2]=ui(uid)
            if cmd in [1,0x10,0x20,0x21]: fields[0x700]=L16(0)
            if cmd==0x21: fields[0x600]=b'MOVE-SCP        '
            if cmd in [1,0x100,0x140]: fields[0x1000]=ui(b'1.2.3.4.5')
            if cmd in [0x110,0x120,0x130,0x150]: fields[0x1001]=ui(b'1.2.3.4.5')
            if cmd==0x100: fields[0x1002]=L16(1)
            if cmd==0x130: fields[0x1008]=L16(1)
            if cmd==0x110: fields[0x1005]=L16(0x10)+L16(0x10)+L16(0x10)+L16(0x20)
            body=b''.join(elem(k,v) for k,v in sorted(fields.items()))
            body=elem(0,L32(len(body)))+body
            emit('dicom',f'dimse-{cmd:04x}-id{mid}',pdu(4,pdv(body)),src,'12 request commands × message ID boundaries')
            if mid==1:
                for split in range(1,len(body)):
                    emit('dicom',f'dimse-{cmd:04x}-split{split}',pdu(4,pdv(body[:split],1))+pdu(4,pdv(body[split:],3)),src,'every command fragment split (odd fragments exercise nonconforming input)',kind='positive' if split%2==0 else 'robustness',packets=2)
                emit('dicom',f'dimse-{cmd:04x}-dataset',pdu(4,pdv(body)+pdv(L16(0x10)+L16(0x10)+L32(4)+b'Doe ',2)),src,'command/data PDV pairing',kind='positive' if cmd not in [0x30,0xfff,0x110,0x150] else 'robustness')
    for pdv_n in [1,2,16,31,32,33]:
        emit('dicom',f'pdv-count-{pdv_n}',pdu(4,b''.join(pdv(bytes([i,0]),2) for i in range(pdv_n))),src,'repeatable PDV cardinality')
    for value in [0,1,65535,0xfffffffa,0xffffffff]:
        emit('dicom',f'invalid-length-{value}',bytes([0x99,0])+B32(value)+bytes(8),src,'PDU length integer overflow',kind='safety',packets=0)
    for typ,body in [(5,bytes(4)),(6,bytes(4)),(7,b'\0\0\0\0'),(7,b'\0\0\2\6')]:
        emit('dicom',f'pdu-{typ}-{body[-1]}',pdu(typ,body),src,'release/abort')


def boundary_regressions():
    src = 'RFC1035 §4.1; RFC6891 §6; RFC8490 §5'
    rr = lambda data: b'\0'+B16(10)+B16(1)+B32(0)+V16(data)
    for count in [65,128,300]:
        emit('dns',f'boundary-answer-count-{count}',B16(7)+B16(0x8000)+B16(0)+B16(count)+bytes(4)+rr(b'abc')*count,src,'section overflow')
    for size in [4097,8192,65000]:
        emit('dns',f'boundary-rdata-{size}',B16(7)+B16(0x8000)+B16(0)+B16(1)+bytes(4)+rr(b'x'*size),src,'RDATA overflow')
    for count in [16,17,32]:
        opts=b''.join(B16(65000+i)+V16(b'') for i in range(count))
        wire=B16(7)+bytes(8)+B16(1)+b'\0'+B16(41)+B16(4096)+bytes(4)+V16(opts)
        emit('dns',f'boundary-edns-options-{count}',wire,src,'option count overflow')
    for count,size in [(17,8),(1,2049),(20,4096)]:
        # Keep the stream message within the 16-bit DNS message size.
        if count*size>65000: continue
        data=b''.join(B16(65000)+V16(b'x'*size) for _ in range(count))
        emit('dns',f'boundary-dso-{count}-{size}',B16(7)+B16(6<<11)+bytes(8)+data,src,'DSO TLV overflow')
    def transport(payload):
        pad=8-(5+len(payload))%8
        if pad<4: pad+=8
        return B32(1+len(payload)+pad)+bytes([pad])+payload+bytes(range(pad))
    for size in [4097,8192]:
        emit('ssh',f'boundary-kex-mpint-{size}',transport(b'\x1e'+S(b'\x01'*size)),'RFC4253 §8','mpint projection overflow')
    emit('ssh','boundary-opaque-large',b'\xff'*70000,'RFC4253 §6','encrypted opaque stream overflow')
    record=lambda data,typ=22: bytes([typ,3,3])+V16(data)
    hs=lambda typ,data: bytes([typ])+V24(data)
    for size in [4097,8192,16000]:
        emit('tls',f'boundary-certificate-{size}',record(hs(11,V24(V24(b'x'*size)))),'RFC5246 §7.4.2','certificate capacity')
    for data in [b'\1',b'\1\0\1\x64',bytes(range(48))]:
        emit('tls',f'boundary-alert-{len(data)}',record(data,21),'RFC5246 §6.2.1, §7.2','fragment/coalesced/ciphertext record')
    first=hs(20,bytes(range(12)))
    following=hs(24,b'\1')
    emit('tls','boundary-fragment-with-following',record(first[:7])+record(first[7:]+following),'RFC5246 §6.2.1','following handshake input lifetime',packets=2)
    pdu=lambda body: b'\4\0'+B32(len(body))+body
    pdv=lambda data: B32(2+len(data))+b'\1\2'+data
    for size in [32769,65536,131072]:
        emit('dicom',f'boundary-pdv-{size}',pdu(pdv(b'x'*size)),'DICOM PS3.8 §9.3.5','PDV payload capacity')
    for count in [65,128]:
        emit('dicom',f'boundary-pdv-count-{count}',pdu(pdv(b'xx')*count),'DICOM PS3.8 §9.3.5','PDV count capacity')


def main():
    global root
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,default=Path(__file__).parent/'corpus')
    args=ap.parse_args();root=args.output;root.mkdir(parents=True,exist_ok=True)
    dns();ssh();tls();dicom();boundary_regressions()
    # Deterministic truncation/length corruptions are safety tests, not positives.
    originals=list(rows)
    for proto in ['dns','ssh','tls','dicom']:
        cases=[r for r in originals if r['protocol']==proto]
        for index,r in enumerate(cases[::max(1,len(cases)//10)][:10]):
            wire=(root/r['path']).read_bytes()
            for cut in sorted(set([0,1,2,3,4,5,len(wire)//2,len(wire)-1])):
                if cut<len(wire):emit(proto,f'truncated-{index}-{cut}',wire[:cut],r['source'],'truncated framing',kind='safety',packets=0)
    (root/'manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(json.dumps({p:sum(r['protocol']==p for r in rows) for p in ['dns','ssh','tls','dicom']}))

if __name__=='__main__':main()
