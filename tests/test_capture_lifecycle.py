#!/usr/bin/env python3
"""No Agent, no inference, no model loading: real capture READY/stop/collect test."""
import argparse,json,pathlib,subprocess,sys,time
sys.path.insert(0,'/home/codex_qwen')
from spark_measurement import SparkSession
B=pathlib.Path('/home/codex_qwen');out=B/'deployment'/('capture-selftest-'+str(time.time_ns()));out.mkdir()
a=argparse.Namespace(timeout=60,tunnel_port=18000,stop_model=False)
s=SparkSession(a,out.name,out);task=None;proc=None
try:
 s.prepare();assert s.meta['warmup']['action']=='skipped','Selftest must not generate/load model'
 task=s.task('capture-lifecycle-only',out);task.start()
 with (out/'capture.log').open('wb') as log:proc=subprocess.Popen(['dumpcap','-q','-i','any','-w',str(out/'raw_traffic.pcapng')],stdout=log,stderr=log,start_new_session=True)
 task.local_ready(proc,out/'raw_traffic.pcapng',out/'capture.log');task.agent_begin();time.sleep(2);task.poll(force=True);task.agent_end();task.before_local_stop();time.sleep(.5);proc.send_signal(2);proc.wait(timeout=10);task.local_stopped()
 r=task.collect();(out/'result.json').write_text(json.dumps({'scope':'capture lifecycle only, no inference/Agent','session':s.meta,'measurement':r},indent=2))
 assert r['server_record_complete'] and r['coverage']['local_covers_agent'],r
 print(json.dumps({'passed':True,'directory':str(out),'coverage':r['coverage'],'analysis':r['server_collection']['analysis']},indent=2))
finally:
 if proc and proc.poll() is None:proc.send_signal(2);proc.wait(timeout=10)
 if task and not task.finished:task.collect()
 s.close()
