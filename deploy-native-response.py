"""Explicit activation of the IPv6 response adapter; preserve the Snort binary."""
import argparse
try:import fcntl
except ImportError:fcntl=None
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

PROGRAM=Path('/opt/ips-console/bin')
LIBRARY=Path('/opt/ips-native-response/1/libips-response.so')
OVERRIDE=Path('/etc/systemd/system/ips.service.d/60-native-response.conf')
BACKUPS=Path('/var/backups/ips-native-response')
LOGS=Path('/var/log/snort')
CHECKPOINT=Path('/var/lib/ips-event-bridge/offsets.json')
INSTANCE=Path('/run/snort/instance.json')
PID=Path('/run/snort/snort.pid')
ENGINE=Path('/opt/ips-snort3/3.12.4.0/bin/snort')
CONFIG=Path('/etc/ips-snort-web.conf')
PROTECTED=(ENGINE,CONFIG,Path('/etc/snort/snort.lua'),
           *[Path('/var/lib/snort/rules')/name for name in ('snort.rules','local.rules','ips-web-hunting.rules','ips-web-bans.rules')])
LOG_NAME=re.compile(r'(?:[0-9]+_)?(?:file_connector_ndr_transmit|alert_json\.txt)')


def run(*args,**kwargs):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=120,**kwargs)
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def active(unit):return subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0


def verified(release):
    release=Path(release)
    manifest=json.loads((release/'manifest.json').read_text())
    if manifest.get('revision')!=1 or manifest.get('architecture')!='aarch64':raise ValueError('Unsupported response adapter')
    if set(manifest['sha256'])!={'libips-response.so','native_response.c','deploy-native-response.py'}:raise ValueError('Unexpected response package files')
    for name,value in manifest['sha256'].items():
        path=release/name
        if path.is_symlink() or digest(path)!=value:raise ValueError('Response package digest mismatch')
    binary=(release/'libips-response.so').read_bytes()
    if binary[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(binary[18:20],'little')!=183:raise ValueError('Expected ARM64 library')
    return manifest


def install(source,target):
    target.parent.mkdir(parents=True,exist_ok=True)
    candidate=target.with_name(target.name+'.new')
    try:shutil.copy2(source,candidate);candidate.chmod(0o644);candidate.replace(target)
    finally:candidate.unlink(missing_ok=True)


def native_logs():
    files=[]
    for path in LOGS.iterdir():
        if not LOG_NAME.fullmatch(path.name):continue
        if path.is_symlink() or not path.is_file() or path.resolve().parent!=LOGS.resolve():raise ValueError('Unsafe native log path')
        files.append(path)
    return files


def drain(instance=None):
    if instance is None:instance=json.loads(INSTANCE.read_text())
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        checkpoint=json.loads(CHECKPOINT.read_text());state=checkpoint['files']
        # Match Bridge.poll's instance boundary. Empty files and files older
        # than this engine instance contain no pending records for its epoch.
        pending=[]
        for path in native_logs():
            info=path.stat()
            if not info.st_size or info.st_mtime<instance['started']:continue
            pending.append(checkpoint.get('epoch')!=instance['epoch'] or
                           state.get(path.name,{}).get('inode')!=info.st_ino or
                           state.get(path.name,{}).get('offset',0)<info.st_size)
        if not any(pending):return
        time.sleep(.25)
    raise RuntimeError('Native event collection did not drain; preserved raw logs require review')


def archive_logs(label):
    destination=LOGS/('.response-'+label)
    destination.mkdir(mode=0o700)
    for path in native_logs():path.rename(destination/path.name)
    return destination


def ready(require_adapter=True):
    from snort_engine import SnortControl
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        try:
            SnortControl().command('show_config_generation()',timeout=2)
            queues={line.split()[0] for line in Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()}
            pid=int(PID.read_text());maps=Path('/proc',str(pid),'maps').read_text()
            if active('ips') and {'0','1','2','3'}<=queues and (not require_adapter or str(LIBRARY) in maps):return
        except (OSError,ValueError,RuntimeError,TimeoutError):pass
        time.sleep(.25)
    raise RuntimeError('Engine listeners or response adapter did not become ready')


def apply(release):
    release=Path(release);verified(release)
    sys.path.insert(0,str(PROGRAM))
    from ips_control import Client
    from snort_engine import configuration_lock
    client=Client(timeout=10)
    for path in (LIBRARY,OVERRIDE):
        if path.is_symlink():raise ValueError('Response installation target is a symlink')
    token=time.strftime('%Y%m%dT%H%M%S')+'-'+str(os.getpid())
    backup=BACKUPS/token;backup.mkdir(parents=True,mode=0o700)
    before={str(p):digest(p) for p in PROTECTED}
    config=json.loads(CONFIG.read_text());database=Path(config['event_db']);inode=database.stat().st_ino
    previous={p:p.read_bytes() if p.exists() else None for p in (OVERRIDE,LIBRARY)}
    for index,(path,value) in enumerate(previous.items()):
        if value is not None:(backup/str(index)).write_bytes(value)
    (backup/'state.json').write_text(json.dumps({'files':{str(p):str(i) if previous[p] is not None else None for i,p in enumerate(previous)},'protected':before}))
    timers=[u for u in ('snort-home-net.timer','ips-log-maintenance.timer') if active(u)]
    stopped=False;log_backup=None
    paused=client.request('maintenance',enabled=True)
    if not paused.get('ok'):raise RuntimeError(paused.get('error','Rule task is running'))
    try:
        environment=dict(os.environ,LD_PRELOAD=str(release/'libips-response.so'))
        run(str(ENGINE),'-V',env=environment)
        for unit in timers:run('systemctl','stop',unit)
        run('systemctl','stop','snort-home-net.service','ips-log-maintenance.service')
        with configuration_lock():
            instance=json.loads(INSTANCE.read_text())
            stopped=True;run('systemctl','stop','ips')
            drain(instance);run('systemctl','stop','ips-event-bridge')
            log_backup=archive_logs(token)
            install(release/'libips-response.so',LIBRARY)
            candidate=backup/'override.conf';candidate.write_text('[Service]\nEnvironment=LD_PRELOAD='+str(LIBRARY)+'\n')
            install(candidate,OVERRIDE)
            run('systemctl','daemon-reload');run('systemctl','start','ips');ready()
            run('systemctl','start','ips-event-bridge')
            if before!={str(p):digest(p) for p in PROTECTED} or inode!=database.stat().st_ino:raise RuntimeError('Protected configuration, engine or database changed')
            (backup/'complete').write_text('Native response adapter active\n')
        print(json.dumps(dict(ok=True,backup=str(backup),native_logs_preserved=str(log_backup),engine_binary_unchanged=True)))
    except BaseException:
        if stopped:
            subprocess.run(['systemctl','stop','ips','ips-event-bridge'],capture_output=True,timeout=120)
            archive_logs(token+'-failed')
            for path,value in previous.items():
                if value is None:path.unlink(missing_ok=True)
                else:
                    saved=backup/('restore-'+path.name);saved.write_bytes(value);install(saved,path)
            run('systemctl','daemon-reload');run('systemctl','start','ips','ips-event-bridge');ready(require_adapter=previous[OVERRIDE] is not None)
        raise
    finally:
        try:
            for unit in timers:run('systemctl','start',unit)
        finally:client.request('maintenance',enabled=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--release',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Run as root')
    with open('/run/ips-deploy.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);apply(args.release)
