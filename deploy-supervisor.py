#!/usr/bin/env python3
"""Validate, back up and activate the detector supervisor without replacing Snort."""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import threading
import time

FILES = ('deploy-supervisor.py', 'deploy-nft.py', 'deployment_support.py')
BACKUPS = Path('/var/backups/ips-supervisor')
ENGINE_PID = Path('/run/snort/snort.pid')
NATIVE_PROGRAM = Path('/opt/ips-console/bin')
LEGACY_PROGRAM = Path('/usr/local/bin')
PROC = Path('/proc')
COMPANIONS = ('ips-web.service', 'ips-event-bridge.service', 'ips-rule-manager.service')


def load(path):
    loader = importlib.machinery.SourceFileLoader(path.stem, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run(*args,input_text=None):
    return subprocess.run(args, input=input_text, check=True, capture_output=True, text=True, timeout=120).stdout


def process(unit):
    return int(run('systemctl', 'show', unit, '-p', 'MainPID', '--value').strip())


@contextmanager
def rule_maintenance():
    from deployment_support import Client
    state = run('systemctl', 'show', 'ips-rule-manager.service', '-p', 'StateDirectory', '--value').strip()
    if state not in ('ips-rule-manager', 'ips-snort-rule-manager') or (Path('/var/lib') / state / 'maintenance').exists():
        raise RuntimeError('Rule manager is already in maintenance or its layout is unknown')
    client = Client(timeout=10)
    response = client.request('maintenance', enabled=True)
    if not response.get('ok'):
        raise RuntimeError(response.get('error', 'A rule operation is running'))
    try:
        yield
    finally:
        response = client.request('maintenance', enabled=False)
        if not response.get('ok'):
            raise RuntimeError(response.get('error', 'Could not resume rule operations'))


def wait_ready(candidate, previous_pid):
    from deployment_support import SnortControl
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            pid = int(ENGINE_PID.read_text())
            if pid != previous_pid and candidate.queue_listeners() == candidate.QUEUE_IDS:
                SnortControl().command('show_config_generation()', timeout=2)
                run('systemctl', 'is-active', '--quiet', 'ips.service')
                return pid
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
        time.sleep(0.5)
    raise RuntimeError('Snort did not reopen the allocated NFQUEUE listeners')


def prepare(output, *, native=True, package=None):
    root = Path(__file__).resolve().parent
    output = output.resolve()
    if output.is_relative_to(root):
        raise ValueError('Stage supervisor releases outside the source directory')
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    for name in FILES:
        data = (root / name).read_bytes().removeprefix(b'\xef\xbb\xbf').replace(b'\r\n', b'\n')
        compile(data, name, 'exec')
        (output / name).write_bytes(data)
        checksums.append(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
    if native:
        if package:
            package=Path(package).resolve()
            expected=package.with_suffix(package.suffix+'.sha256').read_text().split()[0]
            if hashlib.sha256(package.read_bytes()).hexdigest()!=expected:raise ValueError('Supervisor release checksum differs')
            with tarfile.open(package) as bundle:
                for name in ('ips-supervisor','supervisor-build.json','backend-licenses.txt'):
                    (output/name).write_bytes(bundle.extractfile('snort-ndr/'+name).read())
        else:
            from build_tools.go_backend import run as go
            go(['test','-count=1','-timeout=120s','./...'],output/'ips-supervisor')
            spec=json.loads((root/'build_tools/go-sources.json').read_text())
            value=dict(schema=1,backend='go',target='linux-arm64',go_version=spec['version'],sqlite_version=spec['sqliteDriver']['sqliteVersion'],files={'ips-supervisor':hashlib.sha256((output/'ips-supervisor').read_bytes()).hexdigest()})
            (output/'supervisor-build.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
            (output/'ips-supervisor.licenses.txt').replace(output/'backend-licenses.txt')
        (output/'ips-supervisor').chmod(0o755)
        checksums=[]
        for name in (*FILES,'supervisor-build.json','backend-licenses.txt'):
            checksums.append(hashlib.sha256((output/name).read_bytes()).hexdigest()+'  '+name+'\n')
    (output / 'SHA256SUMS').write_text(''.join(checksums), encoding='utf-8', newline='\n')


class NativeSupervisor:
    def __init__(self,count):
        self.QUEUE_IDS=frozenset(map(str,range(count)))

    def queue_listeners(self):
        try:
            rows=Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()
            result=set()
            for row in rows:
                fields=row.split()
                if len(fields)<2 or not all(v.isdecimal() for v in fields[:2]):return None
                if fields[0] in self.QUEUE_IDS and int(fields[1]):result.add(fields[0])
            return result
        except OSError:return None


def native_manifest(release):
    value=json.loads((release/'supervisor-build.json').read_text())
    binary=(release/'ips-supervisor').read_bytes()
    if (value.get('schema')!=1 or value.get('backend')!='go' or value.get('target')!='linux-arm64'
            or set(value.get('files',{}))!={'ips-supervisor'} or len(binary)<64 or binary[:6]!=b'\x7fELF\x02\x01'
            or int.from_bytes(binary[18:20],'little')!=183
            or hashlib.sha256(binary).hexdigest()!=value['files']['ips-supervisor']):
        raise ValueError('Invalid Go supervisor release')
    # SCP from Windows does not retain Unix executable bits. Set them only
    # after validating the staged ELF and its manifest, before the version probe.
    (release/'ips-supervisor').chmod(0o755)
    info=json.loads(run(str((release/'ips-supervisor').resolve()),'--version'))
    if info.get('backend')!='go' or info.get('go_version')!='go'+value['go_version']:raise ValueError('Supervisor runtime differs')
    return value


def queue_policy(table,count,nft):
    import copy
    table=copy.deepcopy(table);found=0
    for obj in table.get('nftables',[]):
        for expr in obj.get('rule',{}).get('expr',[]):
            if 'queue' in expr:
                found+=1;expr['queue']['num']={'range':[0,count-1]} if count>1 else 0
    if found!=1:raise ValueError('Expected one detector queue distribution rule')
    return nft.policy_signature(table)


def queue_count(table):
    counts=[]
    for obj in table.get('nftables',[]):
        for expr in obj.get('rule',{}).get('expr',[]):
            if 'queue' in expr:
                number=expr['queue'].get('num')
                if isinstance(number,dict) and number.get('range',[None])[0]==0:
                    counts.append(number['range'][1]+1)
                elif number==0:counts.append(1)
                else:raise ValueError('Unexpected detector queue range')
    if len(counts)!=1 or not 1<=counts[0]<=65536:raise ValueError('Ambiguous detector queue range')
    return counts[0]


def upgrade_native(release):
    from deployment_support import configuration_lock
    native_manifest(release)
    nft=load(release/'deploy-nft.py')
    program=NATIVE_PROGRAM if (NATIVE_PROGRAM/'ips-supervisor').is_file() else LEGACY_PROGRAM
    target=program/'ips-supervisor';receipt=program/'supervisor-build.json'
    if target.is_symlink() or not target.is_file() or receipt.is_symlink():raise ValueError('Unexpected supervisor destination')
    supervisor_pid=process('ips.service')
    if os.fsencode(target) not in (PROC/str(supervisor_pid)/'cmdline').read_bytes().split(b'\0'):
        raise ValueError('Running detector service does not use this supervisor')
    with rule_maintenance(),configuration_lock():
        engine=int(ENGINE_PID.read_text());companions={unit:process(unit) for unit in COMPANIONS}
        budget=json.loads(run(str((release/'ips-supervisor').resolve()),'resources','--pid',str(engine)))
        count=budget.get('workers')
        if not isinstance(count,int) or not 1<=count<=65536:raise ValueError('Invalid detection service CPU budget')
        table=json.loads(run(nft.NFT,'-j','list','table','inet','ips'))
        previous_count=queue_count(table)
        expected=queue_policy(table,count,nft)
        chain_before=[obj['chain'].get('prio') for obj in table['nftables'] if 'chain' in obj]
        generated=run(str((release/'ips-supervisor').resolve()),'--nft-rules','--queues',str(count))
        run(nft.NFT,'-c','-f','-',input_text=generated)
        backup=BACKUPS/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');backup.mkdir(parents=True,mode=0o700)
        originals={target:(target.read_bytes(),target.stat().st_mode&0o777),receipt:(receipt.read_bytes(),0o644) if receipt.exists() else None}
        for path,previous in originals.items():
            if previous is not None:nft.atomic_write(previous[0],backup/path.name,previous[1])
        replacement={target:(release/'ips-supervisor').read_bytes(),receipt:(release/'supervisor-build.json').read_bytes()}
        restarted=False
        try:
            for path,data in replacement.items():nft.atomic_write(data,path,0o755 if path==target else 0o644)
            restarted=True;run('systemctl','restart','ips.service')
            active_pid=wait_ready(NativeSupervisor(count),engine)
            after=json.loads(run(nft.NFT,'-j','list','table','inet','ips'))
            if (expected!=nft.policy_signature(after) or chain_before!=[obj['chain'].get('prio') for obj in after['nftables'] if 'chain' in obj]
                    or companions!={unit:process(unit) for unit in COMPANIONS}
                    or any(path.read_bytes()!=data for path,data in replacement.items())):
                raise RuntimeError('Go supervisor verification did not preserve services or queue policy')
        except BaseException:
            if restarted:run('systemctl','stop','ips.service')
            for path,previous in originals.items():
                if previous is None:path.unlink(missing_ok=True)
                else:nft.atomic_write(previous[0],path,previous[1])
            if restarted:
                run('systemctl','start','ips.service')
                wait_ready(NativeSupervisor(previous_count),active_pid if 'active_pid' in locals() else engine)
            raise
        print(json.dumps(dict(supervisor_updated=True,backend='go',backup=str(backup),snort_pid=active_pid,workers=count,queues=list(range(count)),companion_services_preserved=True)))


def upgrade(release):
    return upgrade_native(release)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', type=Path)
    mode.add_argument('--release', type=Path)
    parser.add_argument('--package',type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare,native=True,package=args.package)
    else:
        import fcntl
        sys.dont_write_bytecode = True
        program = NATIVE_PROGRAM if (NATIVE_PROGRAM / 'ips-supervisor').is_file() else LEGACY_PROGRAM
        sys.path.insert(0, str(program))
        with open('/run/ips-deploy.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            upgrade(args.release.resolve())
