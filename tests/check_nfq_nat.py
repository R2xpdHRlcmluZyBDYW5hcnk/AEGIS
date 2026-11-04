"""Reproduce inspection coverage around reverse NAT in a disposable Linux kernel."""
import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import time


def run(*args,input=None):
    result=subprocess.run(list(args),input=input,text=True,capture_output=True,timeout=15)
    if result.returncode:raise RuntimeError(result.stderr.strip())
    return result.stdout


def verify():
    # The harness must supply an isolated network/mount namespace (or a VM).
    # Never create this marker on a host's normal /run.
    if not Path('/run/ndr-isolated-vm').exists():raise RuntimeError('Use an isolated Linux network/mount namespace or the ARM64 VM harness')
    if [item['ifname'] for item in json.loads(run('ip','-j','link'))]!=['lo']:
        raise RuntimeError('Expected a fresh network namespace with loopback only')
    for name in ('nat-client','nat-server'):run('ip','netns','add',name)
    server=None
    try:
        for side,namespace,local,remote in (('lan','nat-client','192.0.2.1/24','192.0.2.2/24'),
                                            ('wan','nat-server','198.51.100.1/24','198.51.100.2/24')):
            run('ip','link','add',side,'type','veth','peer','name',side+'-peer')
            run('ip','link','set',side+'-peer','netns',namespace)
            run('ip','addr','add',local,'dev',side);run('ip','link','set',side,'up')
            run('ip','-n',namespace,'addr','add',remote,'dev',side+'-peer')
            run('ip','-n',namespace,'link','set',side+'-peer','up');run('ip','-n',namespace,'link','set','lo','up')
            run('ip','-n',namespace,'route','add','default','via',local.split('/')[0])
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
        run('nft','-f','-',input='table ip nat {\n chain postrouting {\n type nat hook postrouting priority srcnat; policy accept;\n oifname "wan" masquerade\n }\n}\n')
        server_code='''import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('198.51.100.2',18080));s.listen()
for _ in range(2):
 c,_=s.accept();c.recv(64);c.sendall(b'OK');c.close()
s.close()
'''
        server=subprocess.Popen(['ip','netns','exec','nat-server',sys.executable,'-c',server_code],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        time.sleep(.5)
        results=[]
        for priority in (-150,-90):
            rules='''table inet inspection {
counter client_packets {}
counter reply_packets {}
chain prerouting {
type filter hook prerouting priority PRIORITY; policy accept;
iifname "lo" return
fib daddr type { local, broadcast, multicast } return
ip daddr { 224.0.0.0/4, 255.255.255.255 } return
ip saddr 192.0.2.2 counter name client_packets
ip saddr 198.51.100.2 counter name reply_packets
}
}
'''.replace('PRIORITY',str(priority))
            run('nft','-f','-',input=rules)
            # Counters occupy the queue position, so no NFQUEUE listener or
            # packet verdict can affect this hook/exclusion experiment.
            client="import socket; s=socket.create_connection(('198.51.100.2',18080),timeout=5); s.sendall(b'fixture'); assert s.recv(2)==b'OK'; s.close()"
            run('ip','netns','exec','nat-client',sys.executable,'-c',client)
            time.sleep(.1)
            state=json.loads(run('nft','-j','list','table','inet','inspection'))
            counts={obj['counter']['name']:obj['counter']['packets'] for obj in state['nftables'] if 'counter' in obj}
            results.append(dict(priority=priority,**counts));run('nft','delete','table','inet','inspection')
        server.communicate(timeout=5)
        assert results[0]['client_packets']>0 and results[0]['reply_packets']==0,results
        assert results[1]['client_packets']>0 and results[1]['reply_packets']>0,results
        print(json.dumps(dict(nat_inspection_results=results)))
        print('Reverse-NAT replies are excluded before DNAT and visible after DNAT in the synthetic topology')
        source=Path(__file__).resolve().parents[1]/'deploy-nft.py'
        spec=importlib.util.spec_from_file_location('nft_deployer',source)
        deployer=importlib.util.module_from_spec(spec);spec.loader.exec_module(deployer)
        generated=deployer.generated_rules(source.with_name('ips-supervisor'))
        run('nft','-f','-',input=generated.replace('priority -90','priority -150'))
        before=json.loads(run('nft','-j','list','table','inet','ips'))
        for priority in (-90,-150):
            transaction=deployer.priority_transaction(before,priority)
            run('nft','-c','-j','-f','-',input=transaction)
            run('nft','-j','-f','-',input=transaction)
            after=json.loads(run('nft','-j','list','table','inet','ips'))
            assert deployer.policy_signature(before)==deployer.policy_signature(after)
            assert next(item['chain']['prio'] for item in after['nftables'] if 'chain' in item)==priority
        print('Atomic IPS table priority update and rollback verified with the Linux nftables kernel')
    finally:
        if server and server.poll() is None:server.terminate();server.communicate(timeout=5)
        for name in ('nat-client','nat-server'):
            subprocess.run(['ip','netns','delete',name],capture_output=True)


if __name__=='__main__':verify()
