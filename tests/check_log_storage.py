"""Synthetic cross-filesystem bind-mount and clear-boundary integration.

Run as root inside: unshare --mount --propagation private python3 -B ...
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.test_data_layer import m

spec=importlib.util.spec_from_file_location('storage_check',ROOT/'deploy-log-storage.py')
storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)


def run(*args):subprocess.run(args,check=True,capture_output=True)


def main():
    if os.geteuid()!=0:raise SystemExit('Run in a private root mount namespace')
    with tempfile.TemporaryDirectory(prefix='ips-log-storage-check-') as temporary:
        root=Path(temporary);ram=root/'small-volume';ram.mkdir()
        mounted=[]
        try:
            run('mount','-t','tmpfs','-o','size=8m','tmpfs',str(ram));mounted.append(ram)
            source=ram/'ips';source.mkdir();target=root/'persistent/events'
            target.parent.mkdir()
            event=dict(timestamp='2026-11-03T00:00:00Z',event_type='flow',src_ip='192.0.2.1',dest_ip='198.51.100.2',flow={})
            stream=source/'events.json';stream.write_text(json.dumps(event)+'\n')
            info=stream.stat();db=m.EventDB(str(root/'events.db'))
            db.clear(dict(device=info.st_dev,inode=info.st_ino,offset=info.st_size));db.conn.close()
            storage.copy_verified(source,target)
            value=storage.cutoff(root/'events.db')
            value['value']=json.dumps(storage.translate_cutoff(json.loads(value['value']),info,(target/'events.json').stat()))
            storage.cutoff(root/'events.db',value,write=True)
            run('mount','--bind',str(target),str(source));mounted.append(source)
            assert source.stat().st_dev==target.stat().st_dev!=ram.stat().st_dev
            db=m.EventDB(str(root/'events.db'));store=m.EventStore(str(stream));store.db=db
            try:
                store.ingest();db.flush();assert not store.events
                event['timestamp']='2026-11-03T00:00:01Z'
                with stream.open('a') as handle:handle.write(json.dumps(event)+'\n')
                store.last_ingest=0;store.ingest();db.flush()
                assert len(store.events)==1
                assert db.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]==1
            finally:db.conn.close()
            assert len((target/'events.json').read_text().splitlines())==2
        finally:
            for path in reversed(mounted):run('umount',str(path))
    print('PASS: real cross-filesystem bind mount preserves cleared-history boundary and accepts new events')


if __name__=='__main__':main()
