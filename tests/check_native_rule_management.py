"""Synthetic-only integration for the prebuilt session patch and rule-source pipeline."""
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.check_snort_native import prepare,engine,execute,wait_control,records,stop
from tests.snort_pcap import capture
from rule_sources import configure,set_enabled
from snort_rules import update


def read_frames(path):
    data=path.read_bytes();offset=24;frames=[]
    while offset<len(data):
        sec,usec,size,original=struct.unpack_from('<IIII',data,offset);offset+=16
        frames.append((sec,usec,data[offset:offset+size]));offset+=size
    return frames


def write_frames(path,frames):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for sec,usec,frame in frames:
            out.write(struct.pack('<IIII',sec,usec,len(frame),len(frame)));out.write(frame)


def check_sessions(root,config):
    rule=root/'rules/local.rules'
    rule.write_text('alert http any any -> any any (msg:"Session fixture"; http_uri; content:"/ndr-smoke"; sid:9000501; rev:1;)\n')
    capture(root/'one.pcap')
    frames=read_frames(root/'one.pcap')
    write_frames(root/'reuse.pcap',frames+[(sec+2,usec,frame) for sec,usec,frame in frames])
    logs=root/'sessions';logs.mkdir();sock=root/'control.sock'
    with (logs/'engine.log').open('wb') as output:
        process=subprocess.Popen(engine()+['--pause','--control-socket',str(sock),'-c',str(config),'-r',str(root/'reuse.pcap'),'-l',str(logs)],stdout=output,stderr=subprocess.STDOUT)
        try:
            control=wait_control(process,sock)
            control.command('snort.resume(4)',timeout=15)
            time.sleep(.5)
            stats=control.call(['dump-counters'])
            assert stats['dump-counters']['decoder']['pkts']==4,stats
            result=control.call(['ruleset-reload-rules'],timeout=60)
            assert 'ruleset-reload-rules' in result,result
            try: control.command('snort.resume()',timeout=20)
            except RuntimeError: pass
            process.wait(timeout=90)
            assert process.returncode==0,(logs/'engine.log').read_text()[-6000:]
        finally: stop(process)
    data=records(logs)
    http=[e for e in data if e.get('uri')=='/ndr-smoke']
    notices=[e for e in data if e.get('sid')==9000501]
    assert len(http)==2,http
    assert http[0]['uid']==http[1]['uid'],'fixture must reproduce native UID reuse'
    assert http[0]['session_id']!=http[1]['session_id'],http
    assert {e['session_id'] for e in notices}=={e['session_id'] for e in http},notices
    assert any(e.get('ts')==1700000000.03 for e in notices),('alert before reload missing',notices)
    assert {e['session_id'].split(':')[0] for e in http}=={http[0]['session_id'].split(':')[0]}
    again=root/'again';again.mkdir()
    execute(engine()+['-c',str(config),'-r',str(root/'one.pcap'),'-l',str(again)],timeout=90)
    second=next(e for e in records(again) if e.get('uri'))
    assert second['session_id'].split(':')[0]!=http[0]['session_id'].split(':')[0]
    print('PASS session IDs: reused five-tuple separates; notice/HTTP agree across reload; process restart changes prefix')


def check_builtin_suppression(root,config):
    frames=read_frames(root/'one.pcap')
    write_frames(root/'truncated.pcap',[(frames[0][0],0,frames[0][2][:-10])])
    baseline=root/'decoder-before';baseline.mkdir()
    execute(engine()+['-c',str(config),'-r',str(root/'truncated.pcap'),'-l',str(baseline)],timeout=90)
    alerts=[json.loads(line) for p in baseline.glob('*alert_json.txt') for line in p.read_text().splitlines()]
    alert=next(e for e in alerts if e.get('gid')==116)
    (root/'suppress.lua').write_text('suppress = {{gid = 116, sid = '+str(alert['sid'])+'}}\n')
    suppressed=root/'decoder-after';suppressed.mkdir()
    execute(engine()+['-T','-c',str(config)],timeout=90)
    execute(engine()+['-c',str(config),'-r',str(root/'truncated.pcap'),'-l',str(suppressed)],timeout=90)
    after=[json.loads(line) for p in suppressed.glob('*alert_json.txt') for line in p.read_text().splitlines()]
    assert not any(e.get('gid')==116 and e.get('sid')==alert['sid'] for e in after),after
    (root/'suppress.lua').write_text('suppress = {}\n')
    loader=importlib.machinery.SourceFileLoader('native_management_web',str(ROOT/'ips-web'))
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(module)
    from native_rules import parse_builtin
    module.SNORT_CONF=str(config);module.SUPPRESS_LUA=str(root/'suppress.lua')
    module.THRESHOLD_CONF=str(root/'threshold.conf');module.DISABLE_CONF=str(root/'disable.conf')
    (root/'disable.conf').write_text('sid:116:'+str(alert['sid'])+'\n')
    with mock.patch.object(module,'builtin_catalog',return_value=parse_builtin('116:'+str(alert['sid'])+' (decode) fixture\n')):
        module.write_thresholds('',rule_files=[])
        disabled=root/'decoder-disabled';disabled.mkdir()
        execute(engine()+['-T','-c',str(config)],timeout=90)
        execute(engine()+['-c',str(config),'-r',str(root/'truncated.pcap'),'-l',str(disabled)],timeout=90)
        after=[json.loads(line) for p in disabled.glob('*alert_json.txt') for line in p.read_text().splitlines()]
        assert not any(e.get('gid')==116 and e.get('sid')==alert['sid'] for e in after),after
        (root/'disable.conf').write_text('');module.write_thresholds('',rule_files=[])
        restored=root/'decoder-restored';restored.mkdir()
        execute(engine()+['-c',str(config),'-r',str(root/'truncated.pcap'),'-l',str(restored)],timeout=90)
        after=[json.loads(line) for p in restored.glob('*alert_json.txt') for line in p.read_text().splitlines()]
        assert any(e.get('gid')==116 and e.get('sid')==alert['sid'] for e in after),after
        from rule_identity import group_selector
        module.RULES_FILE=str(root/'rules/snort.rules')
        module.LOCAL_RULES=str(root/'rules/local.rules')
        module.HUNT_RULES=str(root/'rules/hunting.rules');module.BAN_RULES=str(root/'rules/bans.rules')
        module.UPDATE_CACHE_DIR=str(root/'empty-cache');module.DIST_RULES_DIR=str(root/'empty-dist')
        module.SOURCES_DIR=str(root/'empty-sources')
        module.save_group_suppressions([group_selector('snort-builtin-116-decode','Snort 内置')])
        module.prepare_thresholds(rule_files=[])
        grouped=root/'decoder-grouped';grouped.mkdir()
        execute(engine()+['-T','-c',str(config)],timeout=90)
        execute(engine()+['-c',str(config),'-r',str(root/'truncated.pcap'),'-l',str(grouped)],timeout=90)
        after=[json.loads(line) for p in grouped.glob('*alert_json.txt') for line in p.read_text().splitlines()]
        assert not any(e.get('gid')==116 and e.get('sid')==alert['sid'] for e in after),after
        module.save_group_suppressions([]);module.prepare_thresholds(rule_files=[])
        text_before=root/'text-group-before';text_before.mkdir()
        execute(engine()+['-c',str(config),'-r',str(root/'one.pcap'),'-l',str(text_before)],timeout=90)
        assert any(e.get('sid')==9000501 for e in records(text_before))
        selector=group_selector('local/local','本地目录')
        assert module.suppress_groups_add([selector])['ok']
        text_after=root/'text-group-after';text_after.mkdir()
        execute(engine()+['-T','-c',str(config)],timeout=90)
        execute(engine()+['-c',str(config),'-r',str(root/'one.pcap'),'-l',str(text_after)],timeout=90)
        assert not any(e.get('sid')==9000501 for e in records(text_after))
        assert any(e.get('uri')=='/ndr-smoke' for e in records(text_after))
        assert module.suppress_groups_remove([selector])['ok']
        text_restored=root/'text-group-restored';text_restored.mkdir()
        execute(engine()+['-c',str(config),'-r',str(root/'one.pcap'),'-l',str(text_restored)],timeout=90)
        assert any(e.get('sid')==9000501 for e in records(text_restored))
    print('PASS native GID:SID management: decoder suppression, generated disable states and re-enable')


def check_custom_sources(root,config):
    text=b'alert ip any any -> any any (msg:"Custom fixture"; sid:9000601; rev:1;)\n'
    bundle=io.BytesIO()
    with tarfile.open(fileobj=bundle,mode='w:gz') as archive:
        payload=b'alert udp any any -> any any (msg:"Archive fixture"; sid:9000602; rev:1;)\n'
        member=tarfile.TarInfo('vendor/protocol.rules');member.size=len(payload)
        archive.addfile(member,io.BytesIO(payload))
    cert,key=root/'cert.pem',root/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,capture_output=True)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Authorization')!='Bearer fixture-token':
                self.send_error(401);return
            if self.path=='/bad': body=b'include /etc/passwd\n'
            elif self.path=='/bundle': body=bundle.getvalue()
            else: body=text
            self.send_response(200);self.end_headers();self.wfile.write(body)
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
    server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    data=root/'custom-updater';data.mkdir()
    directory=data/'update/sources'
    address='https://localhost:'+str(server.server_port)
    settings=root/'rule-update.conf';settings.write_text('ips_policy = balanced\n')
    context=ssl.create_default_context(cafile=str(cert))
    try:
        with mock.patch('ssl._create_default_https_context',return_value=context):
            configure(directory,dict(name='custom/example',label='Fixture',url=address+'/rules',format='rules',token='fixture-token'))
            set_enabled(directory,'custom/example',True)
            configure(directory,dict(name='custom/archive',label='Archive',url=address+'/bundle',format='tar.gz',token='fixture-token'))
            set_enabled(directory,'custom/archive',True)
            update(data,settings)
            compiled=data/'rules/snort.rules';before=compiled.read_bytes()
            assert b'sid:9000601' in before
            assert b'sid:9000602' in before
            update(data,settings,offline=True)
            assert [l for l in compiled.read_text().splitlines() if l.startswith('alert ')]==[l for l in before.decode().splitlines() if l.startswith('alert ')]
            before=compiled.read_bytes()
            (root/'rules/snort.rules').write_bytes(before)
            execute(engine()+['-T','-c',str(config)],timeout=90)
            configure(directory,dict(name='custom/example',url=address+'/bad'))
            try: update(data,settings)
            except ValueError: pass
            else: raise AssertionError('configuration directive accepted as rules')
            assert compiled.read_bytes()==before
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
    print('PASS custom HTTPS source: bearer download, PulledPork3 processing, verified offline cache, native validation and failure preservation')


def check_registered(root,config):
    value=json.load(sys.stdin)
    directory=root/'registered/update/sources'
    configure(directory,dict(name='snort/registered',oinkcode=value['oinkcode'],registered_version='auto'))
    set_enabled(directory,'snort/registered',True)
    settings=root/'rule-update.conf';settings.write_text('ips_policy = balanced\n')
    update(root/'registered',settings)
    (root/'rules/snort.rules').write_bytes((root/'registered/rules/snort.rules').read_bytes())
    execute(engine()+['-T','-c',str(config)],timeout=180)
    print('PASS Registered: authenticated published snapshot download, PulledPork3 processing and native validation')


def main():
    with tempfile.TemporaryDirectory(prefix='ips-native-management-') as temporary:
        root=Path(temporary);config=prepare(root)
        if '--registered-stdin' in sys.argv:
            check_registered(root,config)
            return
        check_sessions(root,config)
        check_builtin_suppression(root,config)
        check_custom_sources(root,config)


if __name__=='__main__': main()
