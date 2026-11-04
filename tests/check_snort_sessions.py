"""Replay synthetic reused tuples through a prebuilt engine and the event database."""
import argparse
import json
from pathlib import Path
import struct
import tempfile

from tests.check_snort_native import engine,execute,prepare,records
from tests.snort_pcap import capture
from tests.test_data_layer import m


def verify(binary=None):
    with tempfile.TemporaryDirectory(prefix='ndr-session-regression-') as temporary:
        root=Path(temporary);config=prepare(root)
        (root/'rules/local.rules').write_text('alert http any any -> any any (msg:"Session fixture"; http_uri; content:"/ndr-smoke"; sid:9000001; rev:1;)\n')
        original=root/'original.pcap';capture(original);raw=original.read_bytes()
        packets=[];offset=24
        while offset<len(raw):
            sec,usec,length,_=struct.unpack_from('<IIII',raw,offset)
            packets.append((sec,usec,raw[offset+16:offset+16+length]));offset+=16+length
        command=engine()
        if binary:command[1 if command[0].endswith('qemu-aarch64') else 0]=str(binary)
        for delay in (2,600):
            logs=root/str(delay);logs.mkdir();pcap=logs/'fixture.pcap'
            with pcap.open('wb') as handle:
                handle.write(raw[:24])
                for shift in (0,delay):
                    for sec,usec,packet in packets:
                        handle.write(struct.pack('<IIII',sec+shift,usec,len(packet),len(packet))+packet)
            execute(command+['-c',str(config),'-r',str(pcap),'-l',str(logs)],timeout=90)
            events=records(logs)
            http=[r for r in events if r.get('id.orig_p')==45000]
            sessions={r.get('session_id') for r in http}
            assert len(sessions)==2 and None not in sessions,'Tuple reuse did not create two engine sessions'
            assert len({r['uid'] for r in http})==1,'Fixture no longer exercises native UID reuse'
            db=m.EventDB(str(logs/'events.db'))
            try:
                for record in events:
                    parsed=m.EventStore._parse(json.dumps(dict(engine='snort3',data=record)))
                    assert parsed is not None;db.add(*parsed)
                db.flush()
                for session in sessions:
                    same=[r for r in http if r['session_id']==session]
                    assert any(r.get('sid')==9000001 for r in same)
                    assert any(r.get('uri')=='/ndr-smoke' for r in same)
                    assert any('orig_pkts' in r for r in same)
                    alert=next(r for r in same if r.get('sid')==9000001)
                    detail=db.security_incident('session:'+session,alert['ts'],alert['ts'],list_view=True)
                    assert detail and detail['incident']['network_count']==len(same),'Full-session evidence was lost at the selected time boundary'
                    assert {db.read_record(r['record_id'])['record']['session_id'] for r in detail['network']}=={session}
            finally:db.conn.close()
        logs=root/'unknown';logs.mkdir();pcap=logs/'fixture.pcap';capture(pcap,application='unknown')
        execute(command+['-c',str(config),'-r',str(pcap),'-l',str(logs)],timeout=90)
        unknown=[r for r in records(logs) if r.get('id.orig_p')==45000]
        assert len(unknown)==1 and unknown[0].get('orig_pkts',0)>1 and unknown[0].get('resp_pkts',0)>1
        assert unknown[0].get('service')=='unknown','Fixture no longer represents an unrecognized application'
        print('Native session identity, complete details and multi-packet unknown TCP with one EOF record verified')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path)
    verify(parser.parse_args().binary)
