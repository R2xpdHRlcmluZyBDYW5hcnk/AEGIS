"""Exercise the native extension and plugin hot loading with synthetic traffic."""
import argparse
import json
from pathlib import Path
import struct
import socket
import shutil
import subprocess
import tempfile
import time

from tests.check_snort_native import engine,execute,prepare,records,stop,wait_control
from tests.snort_pcap import capture,checksum


def fixture(path):
    capture(path,tls_hostname='example.test')
    raw=path.read_bytes();packets=[];offset=24
    while offset<len(raw):
        sec,usec,length,total=struct.unpack_from('<IIII',raw,offset)
        packets.append((sec,usec,raw[offset+16:offset+16+length]));offset+=16+length
    # An established pure ACK after the interval exercises periodic snapshots
    # without manufacturing additional HTTP transactions or changing tuples.
    expanded=packets[:3]+[(packets[2][0]+delay,packets[2][1],packets[2][2]) for delay in (12,24)]+[(sec+24,usec,data) for sec,usec,data in packets[3:]]
    for index,kind in enumerate((8,0)):
        source,target=map(socket.inet_aton,('192.0.2.10','198.51.100.20') if kind==8 else ('198.51.100.20','192.0.2.10'))
        echo=struct.pack('!BBHHH',kind,0,0,42,1)+b'NDR-test'
        echo=echo[:2]+struct.pack('!H',checksum(echo))+echo[4:]
        ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(echo),42,0,64,1,0,source,target)
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
        expanded.append((expanded[-1][0]+1,0,bytes.fromhex('0200000000020200000000010800')+ip+echo))
    with path.open('wb') as handle:
        handle.write(raw[:24])
        for sec,usec,data in expanded:handle.write(struct.pack('<IIII',sec,usec,len(data),len(data))+data)


def verify(plugin,binary=None,previous=None):
    command=engine()
    if binary:command[1 if command[0].endswith('qemu-aarch64') else 0]=str(binary)
    with tempfile.TemporaryDirectory(prefix='ndr-session-logger-') as directory:
        root=Path(directory);config=prepare(root);base=config.read_text()
        (root/'rules/local.rules').write_text('reject icmp any any -> any any (msg:"blocked echo lifecycle"; itype:8; sid:9000092; rev:1;)\n')
        pcap=root/'fixture.pcap';fixture(pcap)
        replacement=root/'replacement.so';shutil.copy2(plugin,replacement)
        for mode in ('startup','enable','reconfigure','replace')+(('legacy',) if previous else ()):
            reload=mode!='startup'
            logs=root/mode;logs.mkdir()
            enabled=base.replace('snapshot_interval = 30','snapshot_interval = 10')
            config.write_text(base if reload else enabled)
            if not reload:
                execute(command+['--plugin-path',str(plugin),'-c',str(config),'-r',str(pcap),'-l',str(logs)],timeout=90)
            else:
                control_path=root/'control.sock'
                with (logs/'process.log').open('wb') as log:
                    initial=['--plugin-path',str(previous if mode=='legacy' else plugin)] if mode in ('reconfigure','replace','legacy') else []
                    process=subprocess.Popen(command+initial+['--pause','--control-socket',str(control_path),'-c',str(config),'-r',str(pcap),'-l',str(logs)],stdout=log,stderr=subprocess.STDOUT)
                    try:
                        control=wait_control(process,control_path);pid=process.pid
                        if initial:
                            control.command('resume(3)',timeout=10)
                            deadline=time.monotonic()+15
                            while not any('"tcp_flags":16' in path.read_text() for path in logs.glob('*ndr_session.json')):
                                if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Initial handshake was not logged')
                                time.sleep(.05)
                        before=control.command('show_config_generation()');config.write_text(enabled)
                        # Both arguments are exact paths created by this harness.
                        path=replacement if mode=='replace' else plugin
                        arguments=json.dumps(str(config))+((','+json.dumps(str(path))) if mode!='reconfigure' else '')
                        reply=control.command('snort.reload_config('+arguments+')',timeout=60)
                        assert not any(word in reply.lower() for word in ('failed','restart required','bad config')),reply
                        deadline=time.monotonic()+60
                        while control.command('show_config_generation()')==before:
                            if time.monotonic()>deadline:raise RuntimeError('Reload generation did not advance')
                            time.sleep(.1)
                        assert process.pid==pid and process.poll() is None
                        result=control.call(['appid-reload-detectors'],timeout=60)
                        assert 'appid-reload-detectors' in result,result
                        try:control.command('resume()',timeout=10)
                        except RuntimeError:pass  # Offline EOF can close the control channel.
                        process.wait(timeout=90)
                    finally:stop(process)
            events=[json.loads(line)['data'] for path in logs.glob('*ndr_session.json') for line in path.read_text().splitlines()]
            by_session={event['session_id'] for event in events}
            for identity in by_session:
                timeline=[event for event in events if event['session_id']==identity]
                beginnings=[i for i,event in enumerate(timeline) if event['event'] in ('start','first_observed')]
                endings=[i for i,event in enumerate(timeline) if event['event']=='end']
                assert len(endings)<=1,(mode,'duplicate end',[event['event'] for event in timeline])
                assert not endings or endings[-1]==len(timeline)-1,(mode,'event after session end',[event['event'] for event in timeline])
                if mode not in ('replace','legacy'):
                    assert len(beginnings)<=1,(mode,'duplicate start',[event['event'] for event in timeline])
            http=[event for event in events if event['dport']==80]
            assert http and {'start','state','update','end'}<={event['event'] for event in http},mode
            if mode in ('startup','enable'):
                assert any(event['appid_service'].lower()=='http' for event in http),mode
            # A surviving connection can lose AppID classification during a
            # detector/configuration reload. The fresh TLS flow must identify.
            assert any(event['appid_service'].lower()=='https' for event in events),mode
            identity={event['session_id'] for event in http};assert len(identity)==1
            assert identity=={event['session_id'] for event in records(logs) if event.get('id.resp_p')==80}
            assert any(event.get('ip_ttl')==64 and event.get('tcp_flags')==2 for event in http)
            assert all(event.get('ip_proto')==6 and event.get('ip_header_len')==20 for event in http if 'packet_ts' in event)
            assert {event.get('icmp_type') for event in events if event['proto']=='ICMP'}>={0,8}
            assert all('NDR-test' not in json.dumps(event) for event in events)
            print('Native lifecycle, periodic snapshots, AppID and extractor identity verified:',mode)
        # Dump wraps readback in inline mode, so the reject action really closes
        # the ICMP flow before FINALIZE_PACKET. Passive replay misses this edge.
        logs=root/'blocked-inline';logs.mkdir();config.write_text(enabled)
        execute(command+['--plugin-path',str(plugin),'-c',str(config),'-r',str(pcap),'-l',str(logs),
            '--daq','pcap','--daq-mode','read-file','--daq','dump','--daq-mode','inline','-Q'],cwd=logs,timeout=90)
        events=[json.loads(line)['data'] for path in logs.glob('*ndr_session.json') for line in path.read_text().splitlines()]
        echoes=[event for event in events if event['proto']=='ICMP' and event.get('icmp_type')==8]
        assert echoes and any(event['event']=='end' for event in echoes),'Reject fixture did not end the ICMP flow'
        for identity in {event['session_id'] for event in echoes}:
            timeline=[event['event'] for event in events if event['session_id']==identity]
            assert timeline==['first_observed','end'],('blocked ICMP reopened',timeline)
        print('Blocked ICMP cannot reopen a closed observation after finalization')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin',type=Path,required=True);parser.add_argument('--binary',type=Path)
    parser.add_argument('--previous-plugin',type=Path,help='Also verify migration from a prior compiled extension')
    args=parser.parse_args();verify(args.plugin,args.binary,args.previous_plugin)
