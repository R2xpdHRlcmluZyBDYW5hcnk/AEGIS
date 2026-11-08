"""Validate an external QUIC handshake/path fixture with the actual decoder."""
import argparse
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile



def verify(pcap,binary,observer=None):
    with tempfile.TemporaryDirectory(prefix='ndr-quic-regression-') as directory:
        root=Path(directory);output=root/'observations.json'
        entry=[str(observer),'quic-observer']
        subprocess.run([*entry,
                        '--pcap',str(pcap),'--tshark',str(binary),'--output',str(output)],check=True,timeout=60)
        events=[json.loads(line) for line in output.read_text().splitlines()]
        assert events,'No decoded QUIC observations'
        assert len({event['data']['session_id'] for event in events})==1,'Fixture must contain one QUIC connection'
        last=events[-1]['data']
        assert len(last['paths'])>=2,'Visible-CID path change was not retained'
        assert last['sni']=='example.test' and 'h3' in last['alpn'],'Synthetic handshake metadata missing'
        assert all(row['engine']=='quic_observer' and row['data']['session_id'] for row in events)
        print('Go observer with actual decoder: handshake, visible path change and source identity verified')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pcap',type=Path,required=True)
    parser.add_argument('--tshark',type=Path,required=True);parser.add_argument('--observer',type=Path,required=True)
    args=parser.parse_args();verify(args.pcap,args.tshark,args.observer)
