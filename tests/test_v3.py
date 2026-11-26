"""Offline verification only. NO Spark connection, model load, or HumanEval run."""
import asyncio
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
from scripts.experiment_config import ExperimentConfig, extract_vllm_args, assert_deployment, PROFILES
from scripts import spark_capture,parse_server_capture,agent_traffic_v3


class ProfileTests(unittest.TestCase):
    def test_four_profiles_output_margin(self):
        for name,(context,limit) in PROFILES.items():
            with self.subTest(name=name):
                cfg=ExperimentConfig.build(name)
                self.assertEqual(cfg.server_context,cfg.codex_context)
                self.assertEqual(cfg.auto_compact_threshold,limit)
                self.assertGreaterEqual(context-limit,1024)
        self.assertEqual(ExperimentConfig.build().server_context,32768)

    def test_8k_16k_32k_catalog_and_codex(self):
        for name in ['baseline-8k','context-16k','context-32k']:
            cfg=ExperimentConfig.build(name)
            with tempfile.TemporaryDirectory() as tmp:
                catalog=Path(tmp)/'catalog.json'
                cfg.update_catalog(ROOT/'config/spark/model_catalog.json',catalog)
                data=json.loads(catalog.read_text())['models'][0]
                self.assertEqual(data['context_window'],cfg.server_context)
                self.assertEqual(data['max_context_window'],cfg.codex_context)
                text=cfg.update_codex((ROOT/'config/spark/config.toml').read_text(),
                                     'http://127.0.0.1:17171/v1')
                self.assertIn(f'model_context_window = {cfg.codex_context}',text)
                self.assertIn(f'model_auto_compact_token_limit = {cfg.auto_compact_threshold}',text)
                self.assertIn('127.0.0.1:17171/v1',text)

    def test_kv_budget_and_bad_intervals(self):
        for value in (-1,0):
            with self.assertRaises(ValueError):ExperimentConfig.build(kv_cache_memory_bytes=value)
        for value in (.3,-1,7):
            with self.assertRaises(ValueError):ExperimentConfig.build(metrics_interval=value)
        with self.assertRaises(ValueError):ExperimentConfig.build(profile='unsupported')
        with self.assertRaises(ValueError):ExperimentConfig('bad',16384,8192,12000).validate()

    def test_live_deployment_strict_match(self):
        cfg=ExperimentConfig.build()
        cmd=['/opt/python','-m','vllm.entrypoints.openai.api_server','--max-model-len','32768',
             '--gpu-memory-utilization','0.70','--max-num-seqs','1','--max-num-batched-tokens','1024',
             '--dtype','bfloat16','--tensor-parallel-size','1','--enforce-eager',
             '--middleware','agent_traffic_v3.AgentTrafficMiddleware']
        actual=extract_vllm_args(cmd)
        self.assertTrue(assert_deployment(actual,cfg))
        with self.assertRaisesRegex(RuntimeError,'server_context'):
            assert_deployment(extract_vllm_args([x if x!='32768' else '8192' for x in cmd]),cfg)
        with self.assertRaisesRegex(RuntimeError,'detailed_events'):
            assert_deployment(extract_vllm_args([x for x in cmd if x!='agent_traffic_v3.AgentTrafficMiddleware']),cfg)

class MetricTests(unittest.TestCase):
    def test_actual_vllm_024_metric_exposure(self):
        text=(ROOT/'fixtures/vllm_0_24_0_metrics.txt').read_text()
        metrics,names,info=spark_capture.parse_prometheus_sample(text)
        self.assertGreater(len(metrics),300)
        self.assertIn('vllm:time_to_first_token_seconds',info['types'])
        self.assertEqual(info['types']['vllm:e2e_request_latency_seconds'],'histogram')
        self.assertTrue(any(m['kind']=='gauge' and m['family']=='vllm:num_requests_running' for m in metrics))
        self.assertTrue(any(m['kind']=='counter' and m['family']=='vllm:prompt_tokens_total' for m in metrics))
        self.assertTrue(any(m['kind']=='histogram' and m['component']=='bucket' for m in metrics))
        self.assertTrue(any(m['kind']=='histogram' and m['component']=='sum' for m in metrics))
        self.assertTrue(any('kv_cache_size_tokens="678446"' in m['labels'] for m in metrics if m['name']=='vllm:cache_config_info'))
        self.assertEqual(len(names),len(set(names)))

    def test_metric_types_and_reset_are_not_request_events(self):
        a='# TYPE vllm:new_gauge gauge\nvllm:new_gauge 1\n# TYPE vllm:new_counter counter\nvllm:new_counter_total 2\n# TYPE vllm:new_hist histogram\nvllm:new_hist_bucket{le="1.0"} 2\nvllm:new_hist_count 3\nvllm:new_hist_sum 0.5\n'
        metrics,names,info=spark_capture.parse_prometheus_sample(a)
        self.assertEqual({m['kind'] for m in metrics},{'gauge','counter','histogram'})
        self.assertEqual({m['component'] for m in metrics if m['kind']=='histogram'},{'bucket','count','sum'})
        self.assertEqual(len(metrics),5)

class TraceTests(unittest.TestCase):
    def test_explicit_join_and_asgi_span_propagation(self):
        packet=[{'type':'sse_event_observed','response_id':'resp-A','model_request_id':'mr-10',
                 'observed_ns':100,'source':'server_pcapng'},
                {'type':'sse_event_observed','response_id':'resp-B','model_request_id':'mr-11',
                 'observed_ns':101,'source':'server_pcapng'}]
        samples=[{'source':'api_server','event_type':'request_receive_start',
                  'asgi_span_id':'span_1','timestamp_ns':102},
                 {'source':'api_server','event_type':'response_headers_ready',
                  'asgi_span_id':'span_1','request_id':'resp-A','timestamp_ns':103},
                 {'source':'scheduler','event_type':'scheduled_chunk','request_id':'resp-B',
                  'num_scheduled_tokens':1024,'timestamp_ns':104},
                 {'source':'sse_encoder','event_type':'sse_encode_done',
                  'response_id':'resp-A','sequence_number':3,'timestamp_ns':105},
                 {'source':'engine_output','event_type':'unknown','request_id':'no-id','timestamp_ns':106}]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'v3_events.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in samples))
            summary={'run_id':'run1','task_id':'HumanEval__0'}
            parse_server_capture._merge_v3_sources(tmp,packet,summary)
            self.assertEqual(summary['v3_explicit_id_matches'],4)
            self.assertEqual(summary['v3_unmatched'],1)
            self.assertEqual(packet[0]['source'],'server_pcapng')
            self.assertEqual(packet[2]['model_request_id'],'mr-10')
            self.assertEqual(packet[4]['model_request_id'],'mr-11')
            self.assertEqual(packet[5]['response_id'],'resp-A')
            self.assertEqual(packet[6]['link_status'],'unmatched')

    def test_ambiguous_must_not_guess(self):
        packet=[{'type':'sse_event_observed','response_id':'dup','model_request_id':'mr-1'},
                {'type':'sse_event_observed','response_id':'dup','model_request_id':'mr-2'}]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'v3_events.jsonl').write_text(json.dumps({'request_id':'dup','timestamp_ns':100,
                 'event_type':'scheduled_chunk','source':'scheduler'})+'\n')
            summary={}
            parse_server_capture._merge_v3_sources(tmp,packet,summary)
            self.assertEqual(packet[-1]['link_status'],'ambiguous')
            self.assertIsNone(packet[-1]['model_request_id'])

    def test_sse_terminal_and_incomplete(self):
        body=(b'event: response.created\ndata: {"type":"response.created","response":{"id":"resp-1"}}\n\n'
              b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp-1","usage":{"input_tokens":5,"output_tokens":2}}}\n\n')
        issues=[]
        msg={'body':body,'maps':[(0,len(body),0)],'chunks':[]}
        stamped=lambda off:(off,off)
        events=list(parse_server_capture._sse_events(msg,stamped,issues,'test'))
        self.assertEqual(len(events),2)
        self.assertEqual(events[-1]['input_tokens'],5)
        self.assertEqual(events[-1]['output_tokens'],2)
        self.assertFalse(issues)
        partial={'body':body+b'event: response.output_text.delta\ndata: {bad',
                 'maps':[(0,len(body)+50,0)],'chunks':[]}
        issues=[]
        list(parse_server_capture._sse_events(partial,stamped,issues,'test'))
        self.assertTrue(any('Incomplete SSE' in x for x in issues))

    def test_tcp_information_not_confused_with_bridge_http(self):
        raw='ESTAB 0 0 192.168.1.4:22 192.168.1.10:33200 users:(("sshd",pid=12,fd=3))\n\t cubic rtt:1.25/0.12 minrtt:0.3 cwnd:10 retrans:0/2 unacked:1 notsent:0 pacing_rate 20Mbps delivery_rate 14Mbps\n'
        sockets=spark_capture.parse_ss_output(raw)
        self.assertEqual(len(sockets),1)
        self.assertEqual(sockets[0]['rtt'],'1.25/0.12')
        self.assertEqual(sockets[0]['layer'],'physical_ssh_transport')
        self.assertNotIn('model_request_id',sockets[0])

    def test_asgi_middleware_events_and_bounded_writer(self):
        async def fakeapp(scope,receive,send):
            await receive()
            scope.setdefault('state',{})['request_metadata']=types.SimpleNamespace(request_id='resp1')
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'two chunks','more_body':False})
        async def rx():return {'type':'http.request','body':b'{"a":1}','more_body':False}
        sent=[]
        async def tx(m):sent.append(m)
        with tempfile.TemporaryDirectory() as tmp:
            prev=(agent_traffic_v3._ENABLED,agent_traffic_v3._LOG_ROOT,
                  agent_traffic_v3._WRITER,agent_traffic_v3._WRITER_PID)
            try:
                agent_traffic_v3._ENABLED=True
                agent_traffic_v3._LOG_ROOT=Path(tmp)
                agent_traffic_v3._WRITER=None;agent_traffic_v3._WRITER_PID=None
                asyncio.run(agent_traffic_v3.AgentTrafficMiddleware(fakeapp)(
                    {'type':'http','path':'/v1/responses','method':'POST',
                     'client':('127.0.0.1',45000),'server':('127.0.0.1',8000),'state':{}},rx,tx))
                agent_traffic_v3._WRITER.close()
                events=[json.loads(line) for file in Path(tmp).glob('events-*.jsonl')
                        for line in file.read_text().splitlines()]
                types_seen={e['event_type'] for e in events}
                self.assertTrue({'request_receive_start','request_body_complete','response_headers_ready',
                    'asgi_send_start','asgi_send_end'}.issubset(types_seen))
                self.assertEqual({e['asgi_span_id'] for e in events if 'asgi_span_id' in e}.__len__(),1)
                self.assertEqual(next(e for e in events if e['event_type']=='request_body_complete')['request_body_bytes'],7)
            finally:
                (agent_traffic_v3._ENABLED,agent_traffic_v3._LOG_ROOT,
                 agent_traffic_v3._WRITER,agent_traffic_v3._WRITER_PID)=prev
            self.assertEqual(len(sent),2)

    def test_writer_bound_no_synced_fsync(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer=agent_traffic_v3.BoundedEventWriter(tmp,max_queue=64,max_bytes=256)
            for i in range(300):writer.emit({'line':'x'*80,'i':i})
            writer.close()
            counts=json.loads(writer.stats_path.read_text())['counts']
            self.assertGreater(counts.get('dropped_log_limit',0)+counts.get('dropped_queue_full',0),0)
            self.assertLessEqual(sum(x.stat().st_size for x in Path(tmp).glob('events-*.jsonl')),16*256)

class SourcePatchTests(unittest.TestCase):
    def test_manifest_hashes_and_syntax(self):
        overlay=ROOT/'vllm_overlay';source=ROOT/'vllm_baseline/vllm'
        meta=json.loads((overlay/'manifest.json').read_text())
        self.assertEqual(meta['version'],'0.24.0')
        for relative,orig_sha in meta['original_sha256'].items():
            self.assertEqual(hashlib.sha256((source/relative).read_bytes()).hexdigest(),orig_sha)
            obj=overlay/'vllm'/relative
            self.assertEqual(hashlib.sha256(obj.read_bytes()).hexdigest(),meta['overlay_sha256'][relative])
            ast.parse(obj.read_text())
        if shutil.which('patch'):
            result=subprocess.run(['patch','-p1','--dry-run','-d',str(ROOT/'vllm_baseline'),
                 '-i',str(overlay/'vllm-0.24.0-telemetry.patch')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_runner_and_server_parse_v3_syntax(self):
        for file in ('run_humaneval_codex.py','spark_measurement.py','scripts/spark_capture.py',
                     'scripts/parse_server_capture.py','scripts/agent_traffic_v3.py',
                     'scripts/experiment_config.py'):
            ast.parse((ROOT/file).read_text())
        if shutil.which('bash'):
            result=subprocess.run(['bash','-n',str(ROOT/'scripts/start_vllm.sh')])
            self.assertEqual(result.returncode,0)

class LegacyEvidenceTests(unittest.TestCase):
    """Existing mounted 8K evidence is read-only; cannot re-decode PCAP without tshark."""
    LEGACY=Path('/mnt/data/20261123-232919-879737.zip')
    @unittest.skipUnless(LEGACY.exists(),'Original two-task ZIP not mounted')
    def test_pcapng_and_legacy_timeline_counts(self):
        with zipfile.ZipFile(self.LEGACY) as z:
            for task in ('0','1'):
                root=f'20261123-232919-879737/HumanEval__{task}/'
                result=json.loads(z.read(root+'result.json'))
                with z.open(root+'server_traffic.pcapng') as f:
                    self.assertEqual(f.read(4),b'\x0a\x0d\x0d\x0a')
                tally=Counter()
                with z.open(root+'server_timeline.jsonl') as f:
                    for line in f:tally[json.loads(line)['type']]+=1
                expected=result['measurement']['server_collection']['analysis']
                self.assertEqual(tally['http_request_start'],expected['http_requests'])
                self.assertEqual(tally['http_response_start'],expected['http_responses'])
                self.assertEqual(tally['sse_event_observed'],expected['sse_events'])

if __name__=='__main__':unittest.main(verbosity=2)
