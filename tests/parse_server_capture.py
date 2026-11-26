#!/usr/bin/env python3
"""Offline packet-observed HTTP/SSE timeline from ONE bridge observation point.

No proxy, no vLLM/engine time claims. TCP retransmission bytes are not counted twice.
Other interfaces remain in PCAPNG, intentionally excluded from aggregate HTTP bytes.
"""
import bisect, collections, hashlib, json, pathlib, re, subprocess, sys
def parse(p):
 s=json.loads((p/'state.json').read_text());pcap=p/'server_traffic.pcapng';events=[];issues=[]
 def event(kind,ns=None,**kw):events.append({'run_id':s['run_id'],'task_id':s['task_id'],'type':kind,'observed_ns':ns,'clock':'Spark CLOCK_REALTIME packet timestamp' if ns else None,**kw})
 event('scope',s.get('ready_ns'),interfaces=s.get('interfaces'),analysis_interface=s.get('analysis_interface'),duplicate_policy='Same HTTP packets can occur at loopback/bridge/veth; timeline uses only bridge. Never sum cross-interface bytes.',unavailable=['engine_enqueue','prefill','decode','kernel_tcp_send_time'],timestamp_semantics='First/last packet carrying reconstructed bytes; not API application receive/send times')
 fields=['frame.time_epoch','frame.interface_name','ip.src','tcp.srcport','ip.dst','tcp.dstport','tcp.seq_raw','tcp.payload','frame.number']
 cmd=['tshark','-n','-r',str(pcap),'-T','fields']
 for f in fields:cmd+=['-e',f]
 r=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
 if r.returncode:raise RuntimeError(r.stderr)
 streams=collections.defaultdict(list);counts=collections.Counter();first=None;last=None;observations={};duplicates=0
 for row in r.stdout.splitlines():
  vals=row.split('\t');vals+=['']*(len(fields)-len(vals));ts,iface,src,sp,dst,dp,seq,payload,frame=vals[:len(fields)]
  if not ts:continue
  ns=int(float(ts)*1e9);first=ns if first is None else min(first,ns);last=ns if last is None else max(last,ns);counts[iface]+=1
  if payload and '8000' in [sp,dp]:
   signature=(src,sp,dst,dp,seq,hashlib.sha256(payload.encode()).hexdigest())
   prior=observations.get(signature)
   if prior and prior[1]!=iface and 0<=ns-prior[0]<=5_000_000:
    event('duplicate_packet_observation',ns,frame=int(frame),interface=iface,reference_frame=prior[2],reference_interface=prior[1],rule='same flow/sequence/payload within 5ms on different interfaces; do not sum');duplicates+=1
   else:observations[signature]=(ns,iface,int(frame))
  if iface!=s.get('analysis_interface') or not payload or '8000' not in [sp,dp]:continue
  try:streams[(src,sp,dst,dp)].append((int(seq),bytes.fromhex(payload.replace(':','')),ns,int(frame)))
  except ValueError:issues.append('Invalid TCP payload field')
 request_count=response_count=sse_count=agent_request_count=0
 for flow,segments in streams.items():
  segments.sort(key=lambda x:(x[0],x[2]));end=segments[0][0];data=bytearray();spans=[]
  for seq,payload,ns,frame in segments:
   if seq>end:
    issues.append(f'TCP gap in {flow}: {seq-end} bytes');break
   skip=max(0,end-seq);piece=payload[skip:]
   if piece:begin=len(data);data.extend(piece);spans.append((begin,len(data),ns,frame));end=seq+len(payload)
  data=bytes(data)
  def stamp(offset):
   for a,b,ns,frame in spans:
    if a<=offset<b:return ns,frame
   return (None,None)
  cursor=0;message_index=0
  while cursor<len(data):
   boundary=data.find(b'\r\n\r\n',cursor)
   if boundary<0:
    if data[cursor:].strip():issues.append(f'Incomplete HTTP headers {flow}')
    break
   header=data[cursor:boundary].decode('latin1');line=header.split('\r\n')[0]
   if not re.match(r'(HTTP/1\.[01] |(?:POST|GET|PUT|DELETE|HEAD|OPTIONS) /)',line):issues.append(f'Unexpected HTTP prefix {flow}');break
   headers={}
   for h in header.split('\r\n')[1:]:
    if ':' in h:k,v=h.split(':',1);headers[k.lower()]=v.strip()
   body_start=boundary+4;body=b'';mapping=[];pos=body_start;complete=True
   if 'chunked' in headers.get('transfer-encoding','').lower():
    while True:
     e=data.find(b'\r\n',pos)
     if e<0:complete=False;break
     try:n=int(data[pos:e].split(b';')[0],16)
     except ValueError:complete=False;break
     pos=e+2
     if n==0:
      trailer=data.find(b'\r\n',pos)
      if trailer<0:complete=False
      else:pos=trailer+2
      break
     if pos+n+2>len(data):complete=False;break
     mapping.append((len(body),len(body)+n,pos));body+=data[pos:pos+n];pos+=n+2
   elif 'content-length' in headers:
    n=int(headers['content-length']);pos=body_start+n;complete=pos<=len(data);body=data[body_start:min(pos,len(data))];mapping=[(0,len(body),body_start)]
   else:
    # Requests without a body, and status codes with no body, have length zero.
    if not line.startswith('HTTP/') or re.match(r'HTTP/1\.[01] (204|304|1\d\d)',line):pos=body_start
    else:body=data[body_start:];pos=len(data);mapping=[(0,len(body),body_start)];complete=False
   start_ns,start_frame=stamp(cursor);end_ns,end_frame=stamp(min(pos,len(data))-1)
   common={'flow':list(flow),'connection_id':'|'.join(sorted([flow[0]+':'+flow[1],flow[2]+':'+flow[3]])),'message_index':message_index,'first_frame':start_frame,'last_frame':end_frame,'http_start_line':line,'headers_bytes':body_start-cursor,'body_bytes':len(body),'http_wire_bytes':min(pos,len(data))-cursor,'byte_accounting':'Count end event only; start repeats reconstructed attributes','message_complete':complete,'completion_observed_ns':end_ns,'request_id':headers.get('x-request-id'),'content_type':headers.get('content-type')}
   if line.startswith('HTTP/'):
    response_count+=1;event('http_response_start',start_ns,status=int(line.split()[1]),**common);event('http_response_end',end_ns,status=int(line.split()[1]),**common)
    if int(line.split()[1])>=400:event('http_error_observed',end_ns,status=int(line.split()[1]),flow=list(flow),message_index=message_index)
   else:
    request_count+=1;agent_request_count+=int(line.split()[1].startswith('/v1/responses'));event('http_request_start',start_ns,method=line.split()[0],path=line.split()[1],measurement_control='measurement_marker=' in line,**common);event('http_request_end',end_ns,**common)
   if 'text/event-stream' in headers.get('content-type',''):
    # SSE split on blank lines; byte timestamp is the last observed packet needed
    # to reconstruct that event, NOT an application encoding timestamp.
    pattern=rb'.*?(?:\r?\n\r?\n)'
    for match in re.finditer(pattern,body,re.S):
     block=match.group();offset=match.end()-1;wire=None
     for a,b,base in mapping:
      if a<=offset<b:wire=base+offset-a;break
     ns,frame=stamp(wire) if wire is not None else (None,None);typ=None
     for l in block.splitlines():
      if l.startswith(b'event:'):typ=l[6:].strip().decode(errors='replace')
      elif l.startswith(b'data:') and typ is None:
       try:typ=json.loads(l[5:]).get('type')
       except (ValueError,AttributeError):pass
     event('sse_event_observed',ns,event_type=typ,event_bytes=len(block),frame=frame,flow=list(flow));sse_count+=1
   if not complete:issues.append(f'Incomplete HTTP message {flow}: {line}');break
   cursor=pos;message_index+=1
 for issue in issues:event('reassembly_error',None,error=issue)
 event('capture_end',s.get('ended_ns'),state=s.get('state'),stop_reason=s.get('stop_reason'),error=s.get('error'))
 events.sort(key=lambda x:x['observed_ns'] or 0)
 with (p/'server_timeline.jsonl').open('w') as f:
  for e in events:f.write(json.dumps(e)+'\n')
 log=(p/'capture.log').read_text(errors='replace');captured=re.search(r'Packets captured:\s*(\d+)',log)
 drops=[int(x) for x in re.findall(r"Packets received/dropped on interface '[^']+':\s*\d+/(\d+)",log)]
 summary={'packet_count':sum(counts.values()),'packets_by_interface':dict(counts),'capture_reported_packets':int(captured.group(1)) if captured else None,'packet_count_matches':bool(captured) and int(captured.group(1))==sum(counts.values()),'dropped_packets':sum(drops) if drops else None,'zero_loss_verified':bool(drops) and not any(drops),'first_packet_ns':first,'last_packet_ns':last,'http_requests':request_count,'agent_responses_requests':agent_request_count,'http_responses':response_count,'sse_events':sse_count,'reassembly_issues':issues,'http_timeline_complete':not issues,'observation_point':s.get('analysis_interface'),'cross_interface_duplicate_accounting':'separate observations, no cross-interface sum for bandwidth','application_timepoints':'unavailable; packet observations only'}
 summary['duplicate_observations_marked']=duplicates;summary['duplicate_rule']='Payload TCP packets with identical flow/sequence/payload within 5ms across interfaces. Lo/proxy connections with different sequence numbers are separate observation layers, never summed.'
 (p/'analysis.json').write_text(json.dumps(summary,indent=2));return summary
if __name__=='__main__':print(json.dumps(parse(pathlib.Path(sys.argv[1]))))
