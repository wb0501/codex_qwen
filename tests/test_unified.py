"""Pure offline tests; no Spark or real Agent execution."""
import hashlib,json,sys,tempfile,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'scripts'))
sys.path.insert(0,str(BASE))
from scripts.spark_capture import parse_ss_output
from scripts.parse_server_capture import classify_compaction,_merge_v3_sources
from scripts.telemetry_merge import parent_response_id,sample_statistics,CORE_FILES
from scripts.convert_legacy_results import convert

def make_fixture(p):
    for name in CORE_FILES:
        if name.endswith('.pcapng'):(p/name).write_bytes(b'\x0a\x0d\x0d\x0a'+b'raw')
        elif name=='result.json':(p/name).write_text(json.dumps({'measurement':{'run_id':'runX','task_id':'GAIA__5'}}))
        elif name=='server_timeline.jsonl':
            items=[{'run_id':'runX','task_id':'GAIA__5','type':'vllm_metrics_sample','event_type':'vllm_metrics_sample','source':'vllm_prometheus_scrape','scrape_start_ns':100,'scrape_end_ns':110,'observed_ns':110},
                   {'run_id':'runX','task_id':'GAIA__5','source':'engine_output','type':'engine_core_output_available','event_type':'engine_core_output_available','pid':12,'monotonic_ns':42,'timestamp_ns':120,'observed_ns':120}]
            (p/name).write_text(''.join(json.dumps(x)+'\n' for x in items))
        else:(p/name).write_text('{}\n')
    (p/'metrics_samples.jsonl').write_text(json.dumps({'scrape_start_ns':100,'observed_ns':110,'metrics':[{'name':'vllm:x_count','kind':'histogram','component':'count','labels':'{a="b"}','value':3}],'raw_text':'# HELP vllm:x test'})+'\n')
    (p/'tcp_samples.jsonl').write_text(json.dumps({'sample_start_ns':115,'observed_ns':120,'raw_output':'0 0 1.2.3.4:22 5.6.7.8:1234','connections':[{'rtt':'1.0/0.2','connection_attribution':'unknown'}]})+'\n')
    (p/'v3_events.jsonl').write_text(json.dumps({'run_id':'runX','task_id':'GAIA__5','pid':12,'monotonic_ns':42,'timestamp_ns':120,'source':'engine_output','event_type':'engine_core_output_available'})+'\n')
    (p/'v3_telemetry_collection.json').write_text(json.dumps({'events':1,'writer_stats':[{'counts':{'written':1}}]}))

class UnifiedTests(unittest.TestCase):
 def test_both_engine_paths(self):
    text=(BASE/'vllm_overlay/vllm/v1/engine/core.py').read_text()
    a=text.split('def step(self)',1)[1].split('def post_step',1)[0]
    b=text.split('def step_with_batch_queue',1)[1].split('def _process_aborts_queue',1)[0]
    for code in (a,b):self.assertIn("'engine_core_output_available'",code)
    self.assertEqual(text.count("'engine_core_output_available'"),2)
 def test_child_parent_only_known_shape(self):
    self.assertEqual(parent_response_id('resp_abc_0-4ef2'),'resp_abc')
    self.assertEqual(parent_response_id('resp_abc_1-4ef2'),'resp_abc')
    self.assertEqual(parent_response_id('resp_abc-odd'),'resp_abc-odd')
    self.assertEqual(parent_response_id('other_abc_0-x'),'other_abc_0-x')
 def test_ss_actual_and_old(self):
    for prefix in ('','ESTAB '):
        raw=prefix+'0 0 10.0.0.1:22 10.0.0.2:52342\n cubic rtt:1.4/0.5 minrtt:0.1 cwnd:10 pacing_rate 223Mbps delivery_rate 42Mbps\n'
        parsed=parse_ss_output(raw)
        self.assertEqual(parsed[0]['rtt'],'1.4/0.5')
        self.assertEqual(parsed[0]['delivery_rate'],'42Mbps')
        self.assertEqual(parsed[0]['connection_attribution'],'unknown')
 def test_compaction_positive_negative(self):
    def b(text,role='developer',index=0,tools=None):
        items=[{'role':'developer','content':[{'text':'agent instructions'}]}, {'role':'assistant','content':[{'text':'history'}]}] if index else []
        items.append({'role':role,'content':[{'text':text}]})
        return json.dumps({'input':items,'tools':tools if tools is not None else []}).encode()
    template='You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another LLM that will resume the task.\nCurrent progress and key decisions made\nImportant context, constraints, or user preferences\nWhat remains to be done (clear next steps)\nAny critical data, examples, or references needed to continue'
    self.assertEqual(classify_compaction(b(template,role='user',index=1))[0],'compaction')
    self.assertEqual(classify_compaction(b(template,role='user'))[0],'unknown')
    self.assertEqual(classify_compaction(b(template,role='user',index=1,tools=[{}]))[0],'unknown')
    self.assertEqual(classify_compaction(b('Please discuss CONTEXT CHECKPOINT COMPACTION as a concept'))[0],'normal')
    self.assertNotEqual(classify_compaction(b('CONTEXT CHECKPOINT COMPACTION\nSummary',role='user'))[0],'compaction')
    self.assertEqual(classify_compaction(b('code solution',tools=[]))[0],'normal')
 def test_monotonic_period_sampling_statistics(self):
    a=sample_statistics([{'observed_ns':t,'scrape_duration_ns':90000000} for t in (1_000_000_000,2_000_000_000,3_250_000_000)],configured_interval=1)
    self.assertEqual(a['interval_max_seconds'],1.25)
    self.assertEqual(a['interval_p50_seconds'],1.125)
 def test_exact_id_join_non_humaneval(self):
    events=[{'type':'sse_event_observed','response_id':'resp_abc','model_request_id':'mr_abc'}]
    with tempfile.TemporaryDirectory() as folder:
        Path(folder,'v3_events.jsonl').write_text(json.dumps({'request_id':'resp_abc_0-ab123','timestamp_ns':100,'source':'scheduler','event_type':'scheduled_chunk'})+'\n')
        summary={'run_id':'r','task_id':'GAIA__5'}
        _merge_v3_sources(folder,events,summary)
        self.assertEqual(summary['v3_explicit_id_matches'],1)
        self.assertEqual(events[-1]['parent_response_id'],'resp_abc')
 def test_lossless_conversion_and_idempotency(self):
    with tempfile.TemporaryDirectory() as td:
        p=Path(td,'original');p.mkdir();make_fixture(p)
        untouched={f:hashlib.sha256((p/f).read_bytes()).hexdigest() for f in CORE_FILES}
        report=convert(p,Path(td,'out'),dry_run=True)
        self.assertEqual(report['counts']['added'],1)
        self.assertFalse(Path(td,'out').exists())
        converted=convert(p,Path(td,'out'),dry_run=False)
        dest=Path(td,'out');self.assertEqual(set(x.name for x in dest.iterdir()),set(CORE_FILES))
        lines=[json.loads(x) for x in (dest/'server_timeline.jsonl').read_text().splitlines()]
        self.assertEqual(len(lines),3)
        self.assertEqual(sum(x['event_type']=='engine_core_output_available' for x in lines),1)
        self.assertEqual(next(x for x in lines if x['event_type']=='vllm_metrics_sample')['raw_sample']['raw_text'],'# HELP vllm:x test')
        self.assertEqual((json.loads((dest/'result.json').read_text())['measurement']['telemetry']['events']),1)
        for f in CORE_FILES:self.assertEqual(hashlib.sha256((p/f).read_bytes()).hexdigest(),untouched[f])
        with self.assertRaises(FileExistsError):convert(p,dest,dry_run=False)
 def test_failed_conversion_retains_raw(self):
    with tempfile.TemporaryDirectory() as td:
        p=Path(td,'in');p.mkdir();make_fixture(p)
        with (p/'v3_events.jsonl').open('a') as f:f.write('broken-json\n')
        with self.assertRaises(ValueError):convert(p,Path(td,'out'),dry_run=False)
        self.assertTrue((p/'v3_events.jsonl').exists())
        self.assertFalse(Path(td,'out').exists())
if __name__=='__main__':unittest.main()
