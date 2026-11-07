"""Replay synthetic bodies locally: detection sees bytes, metadata logs do not."""
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.check_snort_native import engine, execute, prepare, records
from tests.snort_pcap import capture


def main():
    marker=b'NDR_PRIVATE_BODY_FIXTURE_7cdab94e'
    with tempfile.TemporaryDirectory(prefix='aegis-ndr-metadata-') as directory:
        root=Path(directory);config=prepare(root);logs=root/'logs';logs.mkdir()
        (root/'rules/local.rules').write_text('alert http any any -> any any '
            '(msg:"body detection fixture"; http_client_body; content:"'+marker.decode()+'"; sid:9000091; rev:1;)\n')
        pcap=root/'input.pcap';capture(pcap,request_body=marker,response_body=marker[::-1])
        execute(engine()+['-T','-c',str(config)],timeout=90)
        execute(engine()+['-c',str(config),'-r',str(pcap),'-l',str(logs)],timeout=90)
        rows=records(logs)
        http=[row for row in rows if row.get('method')=='POST']
        assert http and http[0]['request_body_len']==len(marker), 'Upload size missing'
        assert any(row.get('sid')==9000091 for row in rows), 'Body inspection was disabled'
        assert any('query' in row for row in rows), 'DNS metadata missing'
        assert any('orig_pkts' in row for row in rows), 'Connection metadata missing'
        for path in logs.rglob('*'):
            if path.is_file():
                assert not path.name.endswith(('.pcap','.pcapng')), 'Packet capture was enabled'
                raw=path.read_bytes()
                assert marker not in raw and marker[::-1] not in raw, 'Body bytes reached logs'
        print('PASS: configuration, HTTP body detection, upload size, DNS/connection metadata; no body or PCAP output')


if __name__=='__main__':main()
