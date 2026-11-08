#!/usr/bin/env python3
"""Exercise the prebuilt ARM64 engine locally using synthetic traffic only."""
import argparse
import hashlib
import http.client
import json
import io
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import tarfile
import threading
import time

sys.dont_write_bytecode = True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deployment_support import SnortControl as DeploymentControl, PREFIX
from tests.snort_pcap import capture


class SnortControl(DeploymentControl):
    """Test-only inspection of native counter output."""
    def call(self,commands,timeout=10):
        if commands!=['dump-counters']:return super().call(commands,timeout)
        reply=self.command('dump_stats("json")',timeout)
        return {'dump-counters':json.JSONDecoder().raw_decode(reply[reply.index('{'):])[0]}


def execute(args, **kwargs):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout[-16000:])
    return result.stdout


def engine():
    binary=Path(PREFIX)/'bin/snort'
    command=[] if os.uname().machine in ('aarch64','arm64') else ['/usr/bin/qemu-aarch64']
    return command+[str(binary),'--daq-dir',PREFIX+'/lib/daq','--script-path',PREFIX+'/etc/snort']


def prepare(root):
    rules=root/'rules';rules.mkdir()
    appid=root/'appid';(appid/'custom/lua').mkdir(parents=True)
    (appid/'odp').symlink_to(PREFIX+'/share/appid/odp',target_is_directory=True)
    (appid/'custom/lua/bans.lua').write_text('')
    (root/'home-net.lua').write_text('HOME_NET="any"\nEXTERNAL_NET="any"\n')
    (root/'suppress.lua').write_text('suppress = {}\n')
    for name in ('snort.rules','local.rules','ips-web-hunting.rules','ips-web-bans.rules'):
        (rules/name).write_text('')
    config=(ROOT/'snort.lua').read_text().replace('/opt/ips-snort3/3.12.4.0',PREFIX).replace("include '/etc/snort/","include '"+str(root)+'/').replace('/var/lib/snort/rules',str(rules)).replace('/var/lib/snort/appid',str(appid))
    (root/'snort.lua').write_text("io.stdout:setvbuf('no')\n"+config)
    return root/'snort.lua'


def records(logs):
    return [json.loads(line) for path in logs.glob('*file_connector_ndr_transmit') for line in path.read_text().splitlines()]


def wait_control(process,path):
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        if process.poll() is not None:
            raise RuntimeError('Native engine exited before control readiness')
        try:
            control=SnortControl(str(path))
            control.command('help()',timeout=2)
            return control
        except (OSError,RuntimeError,TimeoutError):
            time.sleep(.1)
    raise TimeoutError('Native control socket not ready')


def stop(process):
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill();process.wait()


def check_offline(root,config):
    (root/'rules/local.rules').write_text('alert http any any -> any any (msg:"native HTTP"; http_uri; content:"/ndr-smoke"; sid:9000001; rev:1;)\n'
        'alert dns any any -> any any (msg:"native DNS"; content:"|07|example|04|test|00|"; sid:9000002; rev:1;)\n')
    execute(engine()+['-T','-c',str(config)],timeout=90)
    logs=root/'offline';logs.mkdir();pcap=logs/'fixture.pcap';capture(pcap,tls_hostname='example.test')
    execute(engine()+['-c',str(config),'-r',str(pcap),'-l',str(logs)],timeout=90)
    events=records(logs)
    assert any(row.get('query')=='example.test' for row in events)
    assert any(row.get('uri')=='/ndr-smoke' for row in events)
    assert any(row.get('server_name')=='example.test' for row in events)
    print('Native HTTP, DNS and TLS extraction verified')


def check_inline(root,config,workers=4,ipv6=False,suppressed=False):
    # The outer command must create a new network namespace. Never touch host nft.
    if os.geteuid()!=0 or os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
        raise RuntimeError('Run inline checks with: unshare -n python3 -B tests/check_snort_native.py --inline')
    import http.server
    execute(['ip','link','set','lo','up'])
    source_ip,target_ip=('2001:db8::10','2001:db8::20') if ipv6 else ('192.0.2.10','198.51.100.20')
    for address in (source_ip,target_ip):
        execute(['ip','address','add',address+('/128' if ipv6 else '/32'),'dev','lo',*(['nodad'] if ipv6 else [])])
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload=b'native-inline-ok'
            try:
                self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            except (BrokenPipeError,ConnectionResetError): pass
        def log_message(self,*args): pass
    class Server(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6 if ipv6 else socket.AF_INET
    server=Server((target_ip,18080),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    rule=root/'rules/local.rules'
    rules = ('block http any any -> any any (msg:"inline block"; http_uri; content:"/blocked"; sid:9000011; rev:1;)\n'
             'reject http any any -> any any (msg:"inline reject"; http_uri; content:"/rejected"; sid:9000012; rev:1;)\n')
    quiet = {9000013: ('block', '/quiet-block'), 9000014: ('reject', '/quiet-reject'),
             9000015: ('alert', '/quiet-alert'), 9000016: ('drop', '/quiet-drop')}
    if suppressed:
        rules += ''.join(f'{action} http any any -> any any (msg:"quiet {action}"; http_uri; '
                         f'content:"{path}"; sid:{sid}; rev:1;)\n' for sid,(action,path) in quiet.items())
        (root/'suppress.lua').write_text('suppress = {'+','.join(f'{{gid=1, sid={sid}}}' for sid in quiet)+'}\n')
    rule.write_text(rules)
    logs=root/'inline';logs.mkdir();control_path=root/'inline.sock'
    with (logs/'process.log').open('wb') as log:
        inputs=[part for index in range(workers) for part in ('-i',str(index))]
        # Loopback OUTPUT exposes partial offload checksums before completion.
        environment=dict(os.environ)
        if environment.get('NDR_RESPONSE_LIBRARY'):environment['LD_PRELOAD']=environment['NDR_RESPONSE_LIBRARY']
        process=subprocess.Popen(engine()+['--control-socket',str(control_path),'-c',str(config),'-l',str(logs),'-k','none','--daq','nfq','-Q','-z',str(workers),*inputs],stdout=log,stderr=subprocess.STDOUT,env=environment)
        try:
            try: wait_control(process,control_path)
            except Exception:
                log.flush()
                raise RuntimeError((logs/'process.log').read_text()[-12000:])
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                queues=Path('/proc/net/netfilter/nfnetlink_queue').read_text()
                if {str(index) for index in range(workers)} <= {line.split()[0] for line in queues.splitlines()}:
                    break
                time.sleep(.1)
            else: raise RuntimeError('NFQ listeners were not registered')
            queue='0-3' if workers==4 else '0'
            # Production queues PREROUTING. This OUTPUT-only loopback fixture
            # must let locally injected reject RSTs leave without reinspection.
            family='ip6' if ipv6 else 'ip'
            execute(['nft','-f','-'],input='table inet native_test {\n chain output {\n type filter hook output priority mangle; policy accept;\n tcp flags & rst == rst return\n '+family+' saddr {'+source_ip+','+target_ip+'} tcp sport 18080 queue flags bypass to '+queue+'\n '+family+' saddr '+source_ip+' tcp dport 18080 queue flags bypass to '+queue+'\n }\n}\n')
            def request(path):
                connection=http.client.HTTPConnection(target_ip,18080,timeout=3,source_address=(source_ip,0))
                try:
                    connection.request('GET',path,headers={'Host':'example.test'})
                    return connection.getresponse().read()
                finally: connection.close()
            assert request('/allowed')==b'native-inline-ok'
            blocked = ['/blocked','/rejected']
            if suppressed:
                assert request('/quiet-alert')==b'native-inline-ok'
                blocked.extend(['/quiet-block','/quiet-reject'])
            for path in blocked:
                try: request(path)
                except (OSError,http.client.HTTPException) as exc:
                    if path in ('/rejected','/quiet-reject') and isinstance(exc,TimeoutError):
                        raise AssertionError('Native reject timed out instead of resetting the connection') from exc
                else:
                    counters=SnortControl(str(control_path)).call(['dump-counters'])
                    raise AssertionError('Inline rule did not stop '+path+'\n'+json.dumps(counters)+'\n'+json.dumps(records(logs))+'\n'+(logs/'process.log').read_text()[-3000:])
            if suppressed:
                def dropped_packets():
                    counters=SnortControl(str(control_path)).call(['dump-counters'])['dump-counters']
                    return counters['native']['daq'].get('block',0)
                before=dropped_packets()
                # A packet-level drop need not prevent a successful TCP retransmission.
                try: request('/quiet-drop')
                except TimeoutError: pass
                assert dropped_packets()>before
            assert request('/allowed-again')==b'native-inline-ok'
            counters=SnortControl(str(control_path)).call(['dump-counters'])
            assert counters['dump-counters']['ips']['rejected']>0,counters
            if environment.get('NDR_RESPONSE_LIBRARY'):
                active=counters['dump-counters']['native'].get('active',{})
                assert active.get('injects',0)>=2 and not active.get('failed_injects',0),active
        finally:
            subprocess.run(['nft','delete','table','inet','native_test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            stop(process);server.shutdown();server.server_close();thread.join(timeout=5)
    events=records(logs)
    for sid in (9000011,9000012):
        hit=[event for event in events if event.get('sid')==sid]
        assert hit and hit[0].get('ips_action') in ('block','reject'),hit
        assert not any(event.get('alert_suppressed') for event in hit),hit
    if suppressed:
        for sid,(action,_) in quiet.items():
            hits=[event for event in events if event.get('sid')==sid]
            if action=='alert':
                assert not hits,hits
                continue
            assert hits and len({event['pkt_num'] for event in hits})==len(hits),hits
            for hit in hits:
                assert hit['ips_action']==action and hit['session_id'] and hit['alert_suppressed'],hit
        alerts=[json.loads(line) for path in logs.glob('*alert_json.txt') for line in path.read_text().splitlines()]
        assert all(event.get('sid') not in quiet for event in alerts),alerts
        print('Suppressed block, reject and drop retain verdict records; suppressed alerts stay silent')
    print(('IPv6' if ipv6 else 'IPv4')+' four NFQ workers: allowed traffic, actual block/reject and recovery verified in isolated namespace')


def check_suppressed_passive(root,config):
    (root/'rules/local.rules').write_text('block http any any -> any any (msg:"passive block"; '
                                         'http_uri; content:"/ndr-smoke"; sid:9000013; rev:1;)\n')
    logs=root/'passive';logs.mkdir()
    pcap=logs/'fixture.pcap';capture(pcap)
    command=engine()+['-c',str(config),'-r',str(pcap),'-l',str(logs)]
    execute(command,timeout=90)
    assert any(row.get('sid')==9000013 and row.get('action','').startswith('would_') for row in records(logs))
    (root/'suppress.lua').write_text('suppress = {{gid=1, sid=9000013}}\n')
    quiet=root/'passive-suppressed';quiet.mkdir()
    execute(command[:-1]+[str(quiet)],timeout=90)
    assert not any(row.get('sid')==9000013 for row in records(quiet))
    print('Suppressed would-block in passive mode produces no block record')


def check_suppressed_dump(root,config):
    """Exercise real inline verdicts without requiring a host network queue."""
    pcap=root/'suppressed-input.pcap';capture(pcap)
    for index,action in enumerate(('block','reject','drop','alert')):
        sid=9000030+index
        (root/'rules/local.rules').write_text(action+' http any any -> any any '
            '(msg:"suppressed inline replay"; http_uri; content:"/ndr-smoke"; sid:'+str(sid)+'; rev:1;)\n')
        (root/'suppress.lua').write_text('suppress = {{gid=1,sid='+str(sid)+'}}\n')
        logs=root/('suppressed-'+action);logs.mkdir()
        execute(engine()+['-c',str(config),'-r',str(pcap),'-l',str(logs),
            '--daq','pcap','--daq-mode','read-file','--daq','dump','--daq-mode','inline','-Q'],cwd=logs,timeout=90)
        hits=[row for row in records(logs) if row.get('sid')==sid]
        if action=='alert':assert not hits
        else:
            assert hits and all(row.get('alert_suppressed')==1 for row in hits),(action,hits)
            assert len({row['pkt_num'] for row in hits})==len(hits)
            assert all(row.get('ips_action')==action and row.get('alert_suppressed') for row in hits)
    print('Suppressed inline block/reject/drop preserve unique verdict records; suppressed alerts stay silent')


def check_weird_sampling(root,config):
    """Verify the default sampling window without reducing NOTICE coverage."""
    import struct
    from tests.check_native_rule_management import read_frames,write_frames
    source=root/'weird-source.pcap';capture(source)
    frames=read_frames(source)
    query=frames[8][2];response=bytearray(frames[9][2])
    # Obsolete MD resource records produce DNS builtin 131:1.
    response[-14:-12]=struct.pack('!H',3)
    anchor=bytearray(query);anchor[42:44]=struct.pack('!H',5678)
    # An outstanding query keeps the DNS flow open across completed transactions.
    repeated=[(1700000000,0,bytes(anchor))]
    for index in range(2050):
        repeated.extend(((1700000000,index*200+1,query),
            (1700000000,index*200+101,bytes(response))))
    repeated.extend((1700000000+second,0,bytes(anchor)) for second in range(20,600,20))
    repeated.extend(((1700000600,0,query),(1700000600,100,bytes(response))))
    pcap=root/'weird-sampling.pcap';write_frames(pcap,repeated)
    logs=root/'weird-sampling';logs.mkdir()
    execute(engine()+['-c',str(config),'-r',str(pcap),'-l',str(logs)],timeout=90)
    hits=[row for row in records(logs) if row.get('gid')==131 and row.get('sid')==1]
    weird=[row for row in hits if row.get('source')=='dns']
    expected=[3+2*index for index in range(25)]+[2051,4051,len(repeated)]
    assert [row['pkt_num'] for row in weird]==expected
    assert len({row['session_id'] for row in hits})==1,'Fixture must retain one flow'
    assert len([row for row in hits if 'ips_action' in row])==2051,'NOTICE was sampled'
    print('WEIRD defaults verified: first 25, every 1000, reset at 600s; all 2051 NOTICE events retained')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inline',action='store_true')
    parser.add_argument('--ipv6',action='store_true')
    parser.add_argument('--suppressed-blocks',action='store_true')
    parser.add_argument('--workers',type=int,choices=(1,4),default=4)
    args=parser.parse_args()
    binary=Path(PREFIX)/'bin/snort';before=hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='ips-snort-native-') as temporary:
        root=Path(temporary);config=prepare(root)
        if args.suppressed_blocks:
            check_suppressed_passive(root,config)
            if not args.inline:check_suppressed_dump(root,config)
        if args.inline: check_inline(root,config,args.workers,args.ipv6,args.suppressed_blocks)
        else:
            check_weird_sampling(root,config)
            check_offline(root,config)
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==before
    print('Prebuilt engine unchanged; temporary fixtures removed')


if __name__=='__main__': main()
