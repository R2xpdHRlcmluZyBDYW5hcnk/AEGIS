"""Validate an external QUIC handshake/path fixture with the actual decoder."""
import argparse
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile

import quic_observer
from tests.test_data_layer import m


def verify(pcap,binary):
    with tempfile.TemporaryDirectory(prefix='ndr-quic-regression-') as directory:
        root=Path(directory);output=root/'observations.json'
        subprocess.run([sys.executable,'-B',str(Path(quic_observer.__file__).resolve()),
                        '--pcap',str(pcap),'--tshark',str(binary),'--output',str(output)],check=True,timeout=60)
        events=[json.loads(line) for line in output.read_text().splitlines()]
        assert events,'No decoded QUIC observations'
        assert len({event['data']['session_id'] for event in events})==1,'Fixture must contain one QUIC connection'
        last=events[-1]['data']
        assert len(last['paths'])>=2,'Visible-CID path change was not retained'
        assert last['sni']=='example.test' and 'h3' in last['alpn'],'Synthetic handshake metadata missing'
        db=m.EventDB(str(root/'events.db'))
        try:
            for event in events:
                parsed=m.EventStore._parse(json.dumps(event));assert parsed;db.add(*parsed)
            db.flush()
            context=db.session_context(last['session_id'])
            assert context and context['event_counts']['quic']==len(events)
            assert context['records'][0]['sni']=='example.test'
            assert context['records'][0]['coverage']=='passive_visible'
            assert db.conn.execute("SELECT COUNT(*) FROM events WHERE type='flow'").fetchone()[0]==0
        finally:db.conn.close()
        print('Actual decoder handshake, visible path change, source identity and stored evidence verified')
        # Repeat a synthetic Initial across real decoder resets. Connection
        # numbers restart at zero; observations must receive new identities.
        raw=pcap.read_bytes()
        endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}[raw[:4]]
        size=struct.unpack(endian+'IIII',raw[24:40])[2]
        reset_capture=root/'resets.pcap'
        reset_capture.write_bytes(raw[:24]+raw[24:40+size]*9)
        command=quic_observer.command(pcap=reset_capture,binary=str(binary))
        command[command.index('-M')+1]='3'
        decoded=subprocess.run(command,check=True,capture_output=True,text=True,timeout=30)
        observations=[];tracker=quic_observer.Tracker(observations.append)
        frames=[]
        for line in decoded.stdout.splitlines():
            item=quic_observer.packet(line);frames.append(item['frame']);tracker.observe(item)
        tracker.close()
        assert frames.count(1)>=2,frames
        identities={event['data']['session_id'] for event in observations}
        assert len(identities)>=2,'Decoder reset incorrectly merged connection identities'
        print('Actual decoder frame resets preserve distinct session identities:',frames)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pcap',type=Path,required=True)
    parser.add_argument('--tshark',type=Path,required=True);args=parser.parse_args();verify(args.pcap,args.tshark)
