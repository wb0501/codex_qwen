"""Strict historical HTTP body recovery from existing packet frame references.
Only little-endian, single-section Ethernet IPv4 TCP PCAPNG is supported.
No new HTTP transaction association is inferred. Fail closed on missing bytes.
"""
import struct, socket, collections
from pathlib import Path

def packets(path, interface='docker0'):
    flows=collections.defaultdict(list); interfaces=[]; frame=0
    with Path(path).open('rb') as f:
        while (head:=f.read(8)):
            if len(head)!=8:raise ValueError('truncated block header')
            kind,size=struct.unpack('<II',head)
            if size<12 or size%4 or size>64*1024*1024:raise ValueError('invalid block size')
            b=f.read(size-8)
            if len(b)!=size-8 or struct.unpack('<I',b[-4:])[0]!=size:raise ValueError('invalid block trailer')
            if kind==0x0a0d0d0a:
                if interfaces or b[:4]!=b'M<+\x1a':raise ValueError('unsupported section')
            elif kind==1:
                link=struct.unpack_from('<H',b)[0];name=None;i=8
                while i+4<=len(b)-4:
                    code,n=struct.unpack_from('<HH',b,i);i+=4
                    if not code:break
                    if code==2:name=b[i:i+n].decode()
                    i+=(n+3)&~3
                interfaces.append((link,name))
            elif kind==6:
                frame+=1
                iface,hi,lo,cap,wire=struct.unpack_from('<IIIII',b)
                if interfaces[iface][1]!=interface:continue
                if interfaces[iface][0]!=1:raise ValueError('non-Ethernet canonical interface')
                p=b[20:20+cap]
                if len(p)<34 or p[12:14]!=b'\x08\x00':continue
                ip=p[14:];ihl=(ip[0]&15)*4
                if ip[9]!=6 or len(ip)<ihl+20:continue
                if struct.unpack_from('!H',ip,6)[0]&0x3fff:raise ValueError('fragmented IPv4')
                total=struct.unpack_from('!H',ip,2)[0]
                if total>len(ip):raise ValueError('truncated IP payload')
                tcp=ip[ihl:total];sp,dp,seq=struct.unpack_from('!HHI',tcp)
                if 8000 not in (sp,dp):continue
                data=tcp[(tcp[12]>>4)*4:]
                if data:
                    flow=(socket.inet_ntoa(ip[12:16]),str(sp),socket.inet_ntoa(ip[16:20]),str(dp))
                    flows[flow].append((frame,seq,data))
            elif kind in (2,3):raise ValueError('unsupported packet block')
    return flows

def body_for(event,flows):
    try:from .parse_server_capture import _message
    except ImportError:from parse_server_capture import _message
    n=event['http_wire_bytes']; start=event['tcp_seq_raw_start']; first=event['first_frame'];last=event['last_frame']
    if not isinstance(n,int) or n<1 or n>64*1024*1024:raise ValueError('invalid HTTP length')
    data=bytearray(n);covered=bytearray(n)
    items=flows.get(tuple(event['flow']),[])
    if not any(fr==first for fr,_,_ in items) or not any(fr==last for fr,_,_ in items):raise ValueError('frame evidence absent')
    for fr,seq,payload in items:
        if not min(first,last)<=fr<=max(first,last):continue
        offset=(seq-start)&0xffffffff
        if offset>=2**31:offset-=2**32
        a=max(0,offset);b=min(n,offset+len(payload))
        if a>=b:continue
        part=payload[a-offset:b-offset]
        if any(c and x!=y for c,x,y in zip(covered[a:b],data[a:b],part)):raise ValueError('conflicting TCP bytes')
        data[a:b]=part;covered[a:b]=b'\x01'*(b-a)
    if not all(covered):raise ValueError('missing TCP bytes')
    issues=[];msg=_message(bytes(data),0,lambda _: (None,None),issues,tuple(event['flow']))
    if not msg or msg['line']!=event['http_start_line'] or msg['end']!=n or len(msg['body'])!=event['body_bytes'] or msg['complete']!=event['message_complete']:
        raise ValueError('HTTP reconstruction disagrees with original event')
    return msg['body']
