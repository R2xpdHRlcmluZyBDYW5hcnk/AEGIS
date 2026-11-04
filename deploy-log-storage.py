#!/usr/bin/env python3
"""Transactional migration of native logs to a larger persistent volume."""
import argparse
from contextlib import closing
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request

from ips_control import Client
from deployment_layout import layout

ROOT=Path('/var/lib/ips-snort-logs')
BACKUPS=Path('/var/backups/ips-log-storage')
MARKER=Path('/etc/ips-log-storage.json')
UNIT_ROOT=Path('/etc/systemd/system')
LOGS=(Path('/var/log/snort'),Path('/var/log/ips'))
MOUNTS=('var-log-snort.mount','var-log-ips.mount')
SERVICES=('ips','ips-event-bridge','ips-rule-manager','ips-web')
CHECKPOINT=Path('/var/lib/ips-event-bridge/offsets.json')
ROTATION=Path('/etc/logrotate.d/ips-snort')


def run(*args):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout


def private_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    candidate=path.with_suffix('.new')
    try:
        with candidate.open('w') as handle:
            os.chmod(candidate,0o600);json.dump(value,handle,indent=2)
            handle.flush();os.fsync(handle.fileno())
        candidate.replace(path)
    finally:candidate.unlink(missing_ok=True)


def inventory(root):
    result={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('Unsupported log entry: '+str(path))
        if path.is_file():
            digest=hashlib.sha256()
            with path.open('rb') as handle:
                for chunk in iter(lambda:handle.read(1<<20),b''):digest.update(chunk)
            result[path.relative_to(root).as_posix()]=digest.hexdigest()
    return result


def copy_verified(source,target):
    before=inventory(source)
    shutil.copytree(source,target,copy_function=shutil.copy2)
    if before!=inventory(target) or before!=inventory(source):
        raise RuntimeError('Log copy verification failed')
    return before


def translate_cutoff(value,old_info,new_info):
    if value and (value.get('device'),value.get('inode'))==(old_info.st_dev,old_info.st_ino):
        if value['offset']>new_info.st_size:raise ValueError('Invalid log clear boundary')
        return dict(value,device=new_info.st_dev,inode=new_info.st_ino)
    return value


def cutoff(db,value=None,write=False):
    with closing(sqlite3.connect(db,timeout=10)) as conn,conn:
        if not write:
            row=conn.execute("SELECT value FROM event_state WHERE key='stream_cutoff'").fetchone()
            return dict(exists=bool(row),value=row[0] if row else None)
        if value['exists']:
            conn.execute("INSERT INTO event_state VALUES('stream_cutoff',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(value['value'],))
        else:conn.execute("DELETE FROM event_state WHERE key='stream_cutoff'")


def healthy(config):
    spec=importlib.util.spec_from_file_location('log_storage_backend',Path(__file__).with_name('deploy-backend.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.wait_ready(config)
    for name in SERVICES:run('systemctl','is-active','--quiet',name)
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        queues=Path('/proc/net/netfilter/nfnetlink_queue').read_text()
        if {'0','1','2','3'} <= {line.split()[0] for line in queues.splitlines()}:return
        time.sleep(1)
    raise RuntimeError('Snort NFQUEUE listeners not ready')


def bridge_drained(paths,state):
    for path in paths:
        info=path.stat();position=state.get(path.name,{})
        if position.get('inode')!=info.st_ino:return False
        offset=position.get('offset',0)
        if offset==info.st_size:continue
        # A stopped writer cannot complete a final torn line left by a full
        # partition. Retain it in the verified archive rather than discarding it.
        if not 0<info.st_size-offset<=1<<20:return False
        with path.open('rb') as handle:
            handle.seek(offset)
            if b'\n' in handle.read():return False
    return True


def stop_services(config):
    run('systemctl','stop','ips-log-maintenance.timer','ips-log-maintenance.service','snort-home-net.timer')
    instance=Path('/run/snort/instance.json')
    generation=json.loads(instance.read_text())
    run('systemctl','stop','ips')
    # RuntimeDirectory is removed when the detector stops. Retain its last epoch
    # long enough for the normal collector to drain the closed native log files.
    private_json(instance,generation)
    # The detector is stopped; the normal bridge drains its existing log files.
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        state=json.loads(CHECKPOINT.read_text()).get('files',{})
        paths=list(LOGS[0].glob('*file_connector_ndr_transmit'))+list(LOGS[0].glob('*alert_json.txt'))
        paths=[p for p in paths if p.stat().st_mtime>=generation['started'] and p.stat().st_size]
        if bridge_drained(paths,state):break
        time.sleep(.25)
    else:raise RuntimeError('Event bridge did not finish its production log queue')
    run('systemctl','stop','ips-event-bridge')
    # Wait on production tail progress, without querying or copying the database.
    host=config.get('bind','127.0.0.1')
    if host in ('0.0.0.0','::'):host='127.0.0.1'
    if ':' in host:host='['+host+']'
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        with opener.open('http://'+host+':'+str(config.get('port',9000))+'/healthz',timeout=3) as response:
            if json.load(response).get('ingest_lag_bytes')==0:break
        time.sleep(.5)
    else:raise RuntimeError('Console did not finish its production event queue')
    # Web shutdown flushes its current batch before releasing the database.
    run('systemctl','stop','ips-web','ips-rule-manager')


def resume(state):
    run('systemctl','start',*SERVICES)
    for timer,enabled in state['timers'].items():
        if enabled:run('systemctl','start',timer)


def rollback(backup):
    backup=Path(backup).resolve()
    if backup.parent!=BACKUPS.resolve():raise ValueError('Rollback must use a migration backup')
    state=json.loads((backup/'state.json').read_text())
    run('systemctl','stop','ips-log-maintenance.timer','ips-log-maintenance.service','snort-home-net.timer',*reversed(SERVICES))
    for mount in reversed(MOUNTS):
        subprocess.run(['systemctl','stop',mount],check=False,capture_output=True)
        subprocess.run(['systemctl','disable',mount],check=False,capture_output=True)
    for source in LOGS:
        original=Path(state['originals'][str(source)])
        if original.exists():
            if source.exists():source.rmdir()
            original.rename(source)
        elif state.get('released_source'):
            if source.exists():source.rmdir()
            if state.get('logs_removed'):source.mkdir(mode=0o755)
            else:copy_verified(backup/('logs-'+source.name),source)
    if 'cutoff_before' in state:
        restored=state['cutoff_before']
        if state.get('logs_removed'):restored=dict(exists=True,value='null')
        # A completed migration may need to copy back, producing a new inode.
        value=json.loads(restored['value']) if restored['exists'] else None
        if value:
            old=state['old_event_identity'];current=(LOGS[1]/'events.json').stat()
            if (value.get('device'),value.get('inode'))==(old['device'],old['inode']):
                value.update(device=current.st_dev,inode=current.st_ino)
                restored=dict(exists=True,value=json.dumps(value))
        cutoff(state['database'],restored,write=True)
    for target,saved in state['files'].items():
        path=Path(target)
        if saved is None:path.unlink(missing_ok=True)
        else:shutil.copy2(backup/saved,path)
    run('systemctl','daemon-reload');resume(state)
    healthy(state['config'])
    print(json.dumps(dict(log_storage_rollback=True,backup=str(backup))))


def apply(release):
    release=Path(release).resolve()
    if MARKER.exists():
        if not all(os.path.ismount(path) for path in LOGS):raise RuntimeError('Persistent log mount is unavailable')
        print(json.dumps(dict(log_storage_unchanged=True)));return
    if ROOT.exists():raise RuntimeError('Persistent log directory already exists; inspect prior migration first')
    fs=run('findmnt','--noheadings','--output','FSTYPE','--target',str(ROOT.parent)).strip()
    if fs in ('tmpfs','ramfs'):raise ValueError('Persistent log destination is memory-backed')
    for path in LOGS:
        if path.is_symlink() or not path.is_dir() or os.path.ismount(path):raise ValueError('Unexpected source log directory')
    for name in MOUNTS:
        if (UNIT_ROOT/name).exists():raise ValueError('Unrecognized existing log mount unit')
    required=sum(p.stat().st_size for root in LOGS for p in root.rglob('*') if p.is_file())*2+(256<<20)
    if shutil.disk_usage(ROOT.parent).free<required:raise ValueError('Insufficient persistent disk space for verified log copies')
    client=Client();paused=client.request('maintenance',enabled=True)
    if not paused.get('ok'):raise RuntimeError('Rule manager is busy; retry after its current task')
    token=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup=BACKUPS/token;backup.mkdir(parents=True,mode=0o700)
    config=json.loads(Path(layout()['config']).read_text())
    state=dict(config=config,database=config['event_db'],files={},originals={},timers={})
    for timer in ('ips-log-maintenance.timer','snort-home-net.timer'):
        state['timers'][timer]=subprocess.run(['systemctl','is-active','--quiet',timer]).returncode==0
    targets=[UNIT_ROOT/name for name in MOUNTS]+[ROTATION,MARKER]
    targets += [UNIT_ROOT/(name+'.service.d')/'60-log-storage.conf' for name in (*SERVICES,'ips-log-maintenance')]
    targets += [UNIT_ROOT/'ips-log-maintenance.timer.d/60-log-storage.conf']
    for index,path in enumerate(targets):
        name='file-'+str(index) if path.exists() else None
        if name:shutil.copy2(path,backup/name)
        state['files'][str(path)]=name
    for path in LOGS:state['originals'][str(path)]=str(path.with_name('.'+path.name+'-ips-before-'+token))
    private_json(backup/'state.json',state)
    shutil.copy2(Path(__file__),backup/'deploy-log-storage.py')
    # Rollback's imports must survive removal of the deployment staging directory.
    for name in ('ips_control.py','deployment_layout.py','deploy-backend.py'):
        shutil.copy2(release/name,backup/name)
    script=backup/'rollback.sh'
    script.write_text('#!/bin/sh\nset -eu\nexec python3 -B '+str(backup/'deploy-log-storage.py')+' --rollback '+str(backup)+'\n');script.chmod(0o700)
    try:
        stop_services(config)
        for path in LOGS:copy_verified(path,backup/('logs-'+path.name))
        state['cutoff_before']=cutoff(state['database'])
        old_event=LOGS[1]/'events.json';old_info=old_event.stat()
        state['old_event_identity']=dict(device=old_info.st_dev,inode=old_info.st_ino)
        ROOT.mkdir(mode=0o755);(ROOT/'snort').mkdir(mode=0o755)
        copy_verified(LOGS[1],ROOT/'events')
        before=state['cutoff_before'];value=json.loads(before['value']) if before['exists'] else None
        if value:
            value=translate_cutoff(value,old_info,(ROOT/'events/events.json').stat())
            cutoff(state['database'],dict(exists=True,value=json.dumps(value)),write=True)
        private_json(backup/'state.json',state)
        for path in LOGS:
            original=Path(state['originals'][str(path)])
            path.rename(original);path.mkdir(mode=original.stat().st_mode & 0o777)
        for name in MOUNTS:shutil.copy2(release/name,UNIT_ROOT/name)
        for service in (*SERVICES,'ips-log-maintenance'):
            path=UNIT_ROOT/(service+'.service.d')/'60-log-storage.conf';path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('[Unit]\nRequiresMountsFor=/var/log/snort /var/log/ips\n')
        timer=UNIT_ROOT/'ips-log-maintenance.timer.d/60-log-storage.conf';timer.parent.mkdir(parents=True,exist_ok=True)
        timer.write_text('[Timer]\nOnBootSec=\nOnBootSec=1min\nOnUnitActiveSec=\nOnUnitActiveSec=1min\nAccuracySec=10s\n')
        shutil.copy2(release/'logrotate-snort',ROTATION)
        run('systemctl','daemon-reload');run('systemctl','enable',*MOUNTS);run('systemctl','start',*MOUNTS)
        if not all(os.path.ismount(path) for path in LOGS):raise RuntimeError('Persistent log bind mount failed')
        run('logrotate','--debug',str(ROTATION))
        resume(state);healthy(config)
        private_json(MARKER,dict(root=str(ROOT),backup=str(backup),mounts=list(MOUNTS)))
        # Only remove verified originals, after the persistent copy and services
        # are healthy. Immutable disk snapshots and all new logs remain retained.
        state['released_source']=True;private_json(backup/'state.json',state)
        for path in LOGS:
            original=Path(state['originals'][str(path)])
            if original.parent!=path.parent or original.name!='.'+path.name+'-ips-before-'+token:
                raise ValueError('Invalid original log cleanup path')
            if inventory(original)!=inventory(backup/('logs-'+path.name)):
                raise RuntimeError('Original logs changed after backup; source cleanup stopped')
            shutil.rmtree(original)
        (backup/'complete').write_text('Persistent logs mounted and services healthy\n')
        print(json.dumps(dict(log_storage_migrated=True,root=str(ROOT),backup=str(backup))))
    except BaseException:
        rollback(backup);raise
    finally:
        try:Client().request('maintenance',enabled=False)
        except OSError:pass


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',type=Path)
    parser.add_argument('--rollback',type=Path)
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run as root')
    import fcntl
    with open('/run/ips-deploy.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.rollback:rollback(args.rollback)
        elif args.release:apply(args.release)
        else:parser.error('Provide --release or --rollback')


if __name__=='__main__':main()
