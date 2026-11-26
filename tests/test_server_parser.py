#!/usr/bin/env python3
"""Small synthetic tests, no capture privileges, model or Agent required."""
import importlib.util,json,pathlib,subprocess,tempfile,unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('parser',pathlib.Path(__file__).parent/'parse_server_capture.py');parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
class ParserTest(unittest.TestCase):
 def check_capture(self,truncate=False):
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp);(p/'state.json').write_text(json.dumps({'run_id':'unit','task_id':'unit','analysis_interface':'docker0','ready_ns':1,'ended_ns':2,'state':'STOPPED'}))
   request=b'POST /v1/responses HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}'
   sse=b'event: response.completed\ndata: {"type":"response.completed"}\n\n'
   response=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n'+hex(len(sse))[2:].encode()+b'\r\n'+sse+b'\r\n0\r\n\r\n'
   rows=[]
   def row(iface,src,sp,dst,dp,seq,payload):rows.append('\t'.join(['1000.'+str(len(rows)).zfill(6),iface,src,str(sp),dst,str(dp),str(seq),payload.hex(),str(len(rows)+1)]))
   row('docker0','1.1.1.1',1234,'172.17.0.2',8000,100,request)
   row('veth1','1.1.1.1',1234,'172.17.0.2',8000,100,request)
   row('docker0','172.17.0.2',8000,'1.1.1.1',1234,250,response[50:-4] if truncate else response[50:])
   row('docker0','172.17.0.2',8000,'1.1.1.1',1234,200,response[:50])
   row('docker0','172.17.0.2',8000,'1.1.1.1',1234,200,response[:50])
   (p/'capture.log').write_text(f"Packets captured: {len(rows)}\nPackets received/dropped on interface 'docker0': {len(rows)}/0\n")
   with patch.object(parser.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'\n'.join(rows),'')):r=parser.parse(p)
   events=[json.loads(l) for l in (p/'server_timeline.jsonl').read_text().splitlines()]
   return r,events
 def test_chunked_sse_reorder_retransmit_and_duplicate_view(self):
  r,e=self.check_capture();self.assertTrue(r['http_timeline_complete']);self.assertEqual(r['http_requests'],1);self.assertEqual(r['http_responses'],1);self.assertEqual(r['sse_events'],1);self.assertEqual(r['duplicate_observations_marked'],1);self.assertTrue(r['packet_count_matches']);self.assertEqual(sum(x['type']=='sse_event_observed' for x in e),1)
 def test_truncation_is_not_complete(self):
  r,e=self.check_capture(True);self.assertFalse(r['http_timeline_complete']);self.assertTrue(r['reassembly_issues'])
if __name__=='__main__':unittest.main()
