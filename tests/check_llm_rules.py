"""Validate all generated rule families against the matching local ARM64 engine."""
import argparse
from pathlib import Path
import tempfile

from tests.check_snort_native import engine,execute,prepare
from llm_assistant import candidates,rule_from_choice


def verify(binary=None):
    command=engine()
    if binary:command[1 if command[0].endswith('qemu-aarch64') else 0]=str(binary)
    base=dict(src='192.0.2.1',dst='198.51.100.2',proto='TCP',dport=80)
    samples=[dict(base,host='example.test',method='GET',url='/ndr-smoke'),dict(base,sni='example.test',dport=443),
             dict(base,dns='example.test',dport=53,proto='UDP'),dict(base,dns='example.test',dport=53),
             dict(base,tcp_flags=3,ip_ttl=32,tcp_window=1024,data_len=0),dict(base,appid_payload='HTTP')]
    choices=[candidates([row])[0] for row in samples[:-1]]+[dict(kind='appid',proto='tcp',dport=80,application='HTTP')]
    with tempfile.TemporaryDirectory(prefix='ndr-rule-check-') as directory:
        root=Path(directory);config=prepare(root);lines=[]
        for index,choice in enumerate(choices):
            result=rule_from_choice(dict(candidate=0,extra=['ttl','window','dsize'] if choice['kind']=='tcp_flags' else []),[choice])
            lines.append(result['rule'].replace('rev:1;',f'sid:{9900100+index}; rev:1;'))
        lines.append(lines[0].replace('alert ','block ',1).replace('sid:9900100;','sid:9900200;'))
        (root/'rules/local.rules').write_text('\n'.join(lines)+'\n')
        execute(command+['-T','-c',str(config)],timeout=90)
        print('Generated HTTP, TLS, DNS, TCP-header and AppID rules passed native Snort configuration validation')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path)
    args=parser.parse_args();verify(args.binary)
