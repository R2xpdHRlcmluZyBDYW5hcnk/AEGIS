#!/usr/bin/env python3
"""Clear native log bytes while retaining the running detection process."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sqlite3
import tempfile
import time
import urllib.request
from contextlib import closing
from deployment_support import log_paths, validate_log_storage

NATIVE,STREAM=log_paths()
CHECKPOINT=Path('/var/lib/ips-event-bridge/offsets.json')
BACKUPS=Path('/var/backups/ips-log-storage')
ACTIVE=re.compile(r'[0-9]+_(?:file_connector_ndr_transmit|alert_json\.txt)')
ARCHIVE=re.compile(ACTIVE.pattern+r'\.[0-9]+(?:\.gz)?')
DATABASE=Path('/var/lib/ips-snort-web/snort-ndr.db')
CONFIG=Path('/etc/ips-snort-web.conf')


def punch_boundary(path):
    """Discard a captured prefix, retaining all later writes and writer offsets."""
    if path.is_symlink():raise ValueError('Refusing linked native log')
    with path.open('r+b',buffering=0) as handle:
        info=os.fstat(handle.fileno());offset=info.st_size
        handle.seek(max(0,offset-1));last=handle.read(1)
        if offset:
            libc=ctypes.CDLL(None,use_errno=True)
            operation=libc.fallocate
            operation.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_longlong,ctypes.c_longlong)
            operation.restype=ctypes.c_int
            if operation(handle.fileno(),3,0,offset):
                error=ctypes.get_errno();raise OSError(error,os.strerror(error),str(path))
            os.fsync(handle.fileno())
        handle.seek(max(0,offset-256))
        digest=hashlib.sha256(handle.read(min(offset,256))).hexdigest()
    return dict(inode=info.st_ino,offset=offset,tail_hash=digest,discarding=last not in (b'',b'\n',b'\0'))


def replace_stream(path,database):
    """Replace the stopped event stream; preserve every persisted event row."""
    path,database=Path(path),Path(database)
    if path.is_symlink() or not path.is_file() or not database.is_file():raise ValueError('Invalid stream/database path')
    original=path.stat()
    descriptor,candidate=tempfile.mkstemp(prefix='.events-clear-',dir=path.parent)
    candidate=Path(candidate)
    try:
        os.fchmod(descriptor,original.st_mode&0o777)
        os.fchown(descriptor,original.st_uid,original.st_gid)
        os.fsync(descriptor);info=os.fstat(descriptor)
        cutoff=dict(device=info.st_dev,inode=info.st_ino,offset=0)
        # Allocate while the old inode still exists; a stale old cutoff cannot
        # accidentally match a reused inode and skip newly collected records.
        with closing(sqlite3.connect(str(database),timeout=15)) as conn:
            with conn:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute('INSERT INTO event_state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                             ('stream_cutoff',json.dumps(cutoff)))
                os.replace(candidate,path)
        return cutoff
    finally:
        os.close(descriptor);candidate.unlink(missing_ok=True)


def private_json(path,value):
    staged=path.with_suffix('.clear-new')
    try:
        with staged.open('w') as handle:
            os.chmod(staged,0o600);json.dump(value,handle);handle.flush();os.fsync(handle.fileno())
        staged.replace(path)
    finally:staged.unlink(missing_ok=True)


def wait_web(drained=False):
    cfg=json.loads(CONFIG.read_text())
    host=cfg.get('bind','127.0.0.1')
    host='127.0.0.1' if host=='0.0.0.0' else '::1' if host=='::' else host
    if ':' in host:host='['+host.strip('[]')+']'
    url='http://%s:%s/healthz'%(host,cfg.get('port',9000))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        try:
            with opener.open(url,timeout=2) as reply:health=json.load(reply)
            if health.get('ok') and (not drained or health.get('ingest_lag_bytes')==0):return
        except (OSError,ValueError):pass
        time.sleep(.2)
    raise RuntimeError('Console did not become ready/drain its event stream')


def clear_all():
    """Stop consumers, cut old inputs, reset stream and restore consumers."""
    subprocess.run(['systemctl','stop','ips-event-bridge'],check=True)
    try:
        wait_web(drained=True)
        subprocess.run(['systemctl','stop','ips-web'],check=True)
        try:
            state=json.loads(CHECKPOINT.read_text())
            state['epoch']=json.loads(Path('/run/snort/instance.json').read_text())['epoch']
            cleared=archives=0
            for path in NATIVE.iterdir():
                if path.is_symlink():continue
                if ACTIVE.fullmatch(path.name):
                    state['files'][path.name]=punch_boundary(path);cleared+=1
                    # Persist each completed boundary even if a later file fails.
                    private_json(CHECKPOINT,state)
                elif ARCHIVE.fullmatch(path.name):path.unlink();archives+=1
            replace_stream(STREAM,DATABASE)
            for path in STREAM.parent.iterdir():
                if re.fullmatch(r'events\.json\.[0-9]+(?:\.gz)?',path.name) and path.is_file() and not path.is_symlink():
                    path.unlink();archives+=1
            return cleared,archives
        finally:subprocess.run(['systemctl','start','ips-web'],check=True)
    finally:
        subprocess.run(['systemctl','start','ips-event-bridge'],check=True)
        wait_web()


def punch_consumed(path,state):
    if path.is_symlink():raise ValueError('Refusing linked native log')
    with path.open('r+b',buffering=0) as handle:
        info=os.fstat(handle.fileno());offset=state.get('offset',0)
        if state.get('inode')!=info.st_ino or not 0<offset<=info.st_size:return False
        handle.seek(max(0,offset-256))
        if hashlib.sha256(handle.read(min(offset,256))).hexdigest()!=state.get('tail_hash'):return False
        libc=ctypes.CDLL(None,use_errno=True)
        operation=libc.fallocate
        operation.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_longlong,ctypes.c_longlong)
        operation.restype=ctypes.c_int
        # KEEP_SIZE | PUNCH_HOLE: delete consumed bytes without changing the
        # live Snort writer's file offset, inode, logical size or unread suffix.
        if operation(handle.fileno(),0x01|0x02,0,offset):
            error=ctypes.get_errno();raise OSError(error,os.strerror(error),str(path))
        os.fsync(handle.fileno())
    return True


def remove_snapshots():
    if not BACKUPS.exists():return 0
    source=Path(__file__).with_name('deploy-log-storage.py')
    spec=importlib.util.spec_from_file_location('native_log_storage',source)
    storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)
    removed=0
    for backup in BACKUPS.iterdir():
        if backup.is_symlink() or not backup.is_dir() or backup.resolve().parent!=BACKUPS.resolve():continue
        state_path=backup/'state.json'
        if not state_path.is_file():continue
        state=json.loads(state_path.read_text())
        if state.get('mode')=='direct':
            # These archives include covered logs and configuration rollback
            # inputs; ordinary consumed-prefix cleanup must retain them.
            continue
        if set(state.get('originals',{}))!={'/var/log/snort','/var/log/ips'}:raise ValueError('Unrecognized log snapshot')
        state['logs_removed']=True
        storage.private_json(state_path,state)
        # Preserve configuration rollback even after old raw logs are deleted.
        shutil.copy2(source,backup/'deploy-log-storage.py')
        for name in ('logs-snort','logs-ips'):
            path=backup/name
            if path.is_symlink() or path.resolve().parent!=backup.resolve() or os.path.ismount(path):
                raise ValueError('Invalid log snapshot cleanup path')
            if path.exists():shutil.rmtree(path);removed+=1
    return removed


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true')
    parser.add_argument('--event-stream',action='store_true',help='Also clear unconsumed native bytes and the console event stream, keeping database history')
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run as root')
    if not args.apply:raise SystemExit('Use --apply only after validating native event ingestion')
    validate_log_storage()
    from deployment_support import Client
    client=Client(timeout=3)
    if not client.request('ping').get('ready'):raise RuntimeError('Rule manager unavailable')
    for unit in ('ips','ips-web','ips-event-bridge'):
        subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
    pid=Path('/run/snort/snort.pid').read_text()
    timer=subprocess.run(['systemctl','is-active','--quiet','ips-log-maintenance.timer']).returncode==0
    paused=client.request('maintenance',enabled=True)
    if not paused.get('ok'):raise RuntimeError(paused.get('error','Rule job is running'))
    try:
        subprocess.run(['systemctl','stop','ips-log-maintenance.timer','ips-log-maintenance.service'],check=True)
        if args.event_stream:
            cleared,archives=clear_all()
        else:
            state=json.loads(CHECKPOINT.read_text())['files']
            cleared=archives=0
            for path in NATIVE.iterdir():
                if path.is_symlink():continue
                if ACTIVE.fullmatch(path.name):cleared+=int(punch_consumed(path,state.get(path.name,{})))
                elif ARCHIVE.fullmatch(path.name):path.unlink();archives+=1
        snapshots=remove_snapshots()
        if Path('/run/snort/snort.pid').read_text()!=pid:raise RuntimeError('Detection process changed during log cleanup')
        print(json.dumps(dict(native_prefixes_cleared=cleared,archives_removed=archives,snapshot_log_directories_removed=snapshots,event_stream_preserved=not args.event_stream,database_preserved=True,engine_preserved=True)))
    finally:
        try:
            if timer:subprocess.run(['systemctl','start','ips-log-maintenance.timer'],check=True)
        finally:client.request('maintenance',enabled=False)


if __name__=='__main__':main()
