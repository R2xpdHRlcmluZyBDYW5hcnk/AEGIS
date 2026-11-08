"""Exercise the native log handoff locally with four synthetic packet workers."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import struct
import tempfile
import threading
import time

from tests.check_snort_native import engine, prepare, wait_control, stop
from tests.snort_pcap import capture


def wait_for(check, description, timeout=30):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if check():return
        time.sleep(.05)
    raise AssertionError(description)


def active_logs(root):
    return sorted(p for p in root.iterdir() if p.is_file() and
                  re.fullmatch(r'(?:\d+_)?(?:file_connector_ndr_transmit|alert_json\.txt|ndr_session\.json)',p.name))


def verify(plugin):
    with tempfile.TemporaryDirectory(prefix='aegis-native-history-') as temporary:
        root=Path(temporary);config=prepare(root)
        (root/'rules/local.rules').write_text('alert udp any any -> any 53 (msg:"History fixture"; sid:9000101; rev:1;)\n')
        pcaps=[];writers=[];finished=threading.Event()
        sample=root/'sample.pcap';capture(sample);packet_bytes=sample.read_bytes()
        frames=[];offset=24
        while offset<len(packet_bytes):
            sec,usec,length,original=struct.unpack_from('<IIII',packet_bytes,offset)
            frames.append((usec,packet_bytes[offset+16:offset+16+length]));offset+=16+length
        def feed(path):
            try:
                with path.open('wb',buffering=0) as output:
                    output.write(packet_bytes[:24])
                    second=1700000000
                    while not finished.is_set():
                        output.write(b''.join(struct.pack('<IIII',second,usec,len(frame),len(frame))+frame for usec,frame in frames))
                        second+=60;finished.wait(.02)
            except BrokenPipeError:pass
        for i in range(4):
            path=root/('worker-'+str(i)+'.pcap');os.mkfifo(path);pcaps.append(str(path))
            writer=threading.Thread(target=feed,args=(path,),daemon=True);writer.start();writers.append(writer)
        logs=root/'logs';logs.mkdir();channel=root/'control.sock'
        retained=b'{"ts":1700000000,"query":"preserved.example.test","trans_id":1}\n'
        (logs/'0_file_connector_ndr_transmit').write_bytes(retained)
        with (root/'engine.log').open('w') as output:
            process=subprocess.Popen(engine()+['--plugin-path',str(plugin),'-c',str(config),'--daq','pcap',
                '--pcap-list',' '.join(pcaps),'-z','4','-l',str(logs),'--control-socket',str(channel)],
                stdout=output,stderr=subprocess.STDOUT,cwd=root)
            try:
                control=wait_control(process,channel);pid=process.pid
                assert 'reopen_logs' in control.command('help()',timeout=10)
                wait_for(lambda:len(active_logs(logs))>=12 and all(p.stat().st_size>0 for p in active_logs(logs)), 'four workers did not write all three log types')
                assert (logs/'0_file_connector_ndr_transmit').read_bytes().startswith(retained),'engine startup truncated unread raw history'
                retired=root/'retired';retired.mkdir()
                old=active_logs(logs)
                for path in old:
                    mode=path.stat().st_mode&0o777;path.rename(retired/path.name);path.touch(mode=mode)
                reply=control.command('reopen_logs()',timeout=60)
                assert 'NDR_LOGS_REOPENED threads=4' in reply,reply
                assert process.poll() is None and process.pid==pid
                wait_for(lambda:all(p.stat().st_size>0 for p in active_logs(logs)), 'new log files did not receive traffic')
                old_sizes={p.name:p.stat().st_size for p in retired.iterdir()}
                time.sleep(.2)
                assert old_sizes=={p.name:p.stat().st_size for p in retired.iterdir()},'a worker kept writing a retired inode'
                # A failed open must retain the old handle and keep processing.
                failure=root/'failed';failure.mkdir();blocked=next(p for p in active_logs(logs) if p.name.endswith('alert_json.txt'))
                blocked.rename(failure/blocked.name);blocked.mkdir()
                reply=control.command('reopen_logs()',timeout=60)
                assert 'NDR_LOGS_REOPEN_FAILED' in reply,reply
                assert process.poll() is None,'failed handoff terminated detection'
                blocked.rmdir();blocked.touch()
                reply=control.command('reopen_logs()',timeout=60)
                assert 'NDR_LOGS_REOPENED threads=4' in reply,reply
                wait_for(lambda:blocked.stat().st_size>0,'log writer did not recover after failed handoff')
                for path in active_logs(logs):
                    for line in path.read_bytes().splitlines(keepends=True):
                        if line.endswith(b'\n'):json.loads(line)
                assert process.poll() is None and process.pid==pid
                print('PASS: four-worker log handoff, buffered old-file isolation, new traffic and failed-open recovery; detector preserved')
            except BaseException:
                print('engine exit:',process.poll())
                print((root/'engine.log').read_text()[-7000:])
                raise
            finally:
                finished.set();stop(process)
                for writer in writers:writer.join(timeout=2)
                assert process.returncode in (0,-15),'native worker teardown failed: '+str(process.returncode)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plugin',required=True,type=Path)
    verify(parser.parse_args().plugin)
