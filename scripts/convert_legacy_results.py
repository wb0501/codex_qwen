#!/usr/bin/env python3
"""Non-destructive 11-file to 7-file conversion. No network or model calls."""
import argparse
from pathlib import Path
import hashlib,json,os,shutil,tempfile
from telemetry_merge import CORE_FILES,EXTRA_FILES,merge_task

def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()

def convert(source,destination,dry_run=True):
    source=Path(source).resolve();destination=Path(destination).resolve()
    if not source.is_dir():raise FileNotFoundError(source)
    if source==destination:raise ValueError('In-place overwrite is disallowed; specify a new output directory')
    if destination.exists():raise FileExistsError('Destination exists; refusing overwrite')
    src_sha={x:sha256(source/x) for x in CORE_FILES if (source/x).is_file()}
    report={'source':str(source),'destination':str(destination),'dry_run':dry_run,
            'original_sha256':src_sha,'available_intermediates':[x for x in EXTRA_FILES if (source/x).exists()]}
    if dry_run:
        _,_,counts=merge_task(source)
        report['counts']=counts
        return report
    destination.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix='.agent-traffic-merge-',dir=destination.parent))
    try:
        for name in CORE_FILES+EXTRA_FILES:
            if (source/name).is_file():shutil.copy2(source/name,staging/name)
        events,result,counts=merge_task(staging)
        out=staging/'server_timeline.jsonl.tmp'
        with out.open('w') as f:
            for event in events:f.write(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n')
            f.flush();os.fsync(f.fileno())
        os.replace(out,staging/'server_timeline.jsonl')
        out=staging/'result.json.tmp'
        with out.open('w') as f:
            json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(out,staging/'result.json')
        for name in ('raw_traffic.pcapng','server_traffic.pcapng'):
            if sha256(staging/name)!=src_sha[name]:raise RuntimeError('PCAP SHA256 changed: '+name)
        for name in EXTRA_FILES:(staging/name).unlink(missing_ok=True)
        if set(x.name for x in staging.iterdir())!=set(CORE_FILES):
            raise RuntimeError('Noncanonical output: not exactly seven files')
        report.update(counts=counts,final_sha256={x:sha256(staging/x) for x in CORE_FILES})
        fd=os.open(staging,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        os.rename(staging,destination)
        fd=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        return report
    except BaseException:
        # Keep staging and all raw evidence for investigation on error.
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,help='Existing 11-file task directory')
    parser.add_argument('--output',required=True,help='NEW output task directory')
    parser.add_argument('--commit',action='store_true',help='Default is dry-run')
    args=parser.parse_args()
    print(json.dumps(convert(args.source,args.output,not args.commit),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
