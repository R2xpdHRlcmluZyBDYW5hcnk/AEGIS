"""Explicit, serialized history reset for the separate native service layout."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.request

STATE=Path('/var/lib/ips-snort-rule-manager')
CONFIG=Path('/etc/ips-snort-web.conf')
WEB_STATE=Path('/var/lib/ips-snort-web')
NATIVE=Path('/var/log/snort')
STREAM=Path('/var/log/ips/events.json')
CHECKPOINT=Path('/var/lib/ips-event-bridge/offsets.json')
NATIVE_NAMES=re.compile(r'(?:[0-9]+_)?(?:file_connector_ndr_transmit|alert_json\.txt|events?\.json)(?:\.[0-9]+(?:\.gz)?)?')
STREAM_NAMES=re.compile(r'events\.json(?:\.[0-9]+(?:\.gz)?)?')
ARCHIVE_NAME=re.compile(r'\.response-[0-9]{8}T[0-9]{6}-[0-9]+(?:-failed)?')


def status(directory):
    try:return json.loads((Path(directory)/'history-reset.json').read_text())
    except FileNotFoundError:return {'state':'idle'}
    except (ValueError,OSError):return {'state':'failed','error':'无法读取历史清空任务状态'}


def save(directory,value):
    path=Path(directory)/'history-reset.json';candidate=path.with_suffix('.new')
    try:
        with candidate.open('w') as handle:
            os.chmod(candidate,0o600);json.dump(value,handle,ensure_ascii=False);handle.flush();os.fsync(handle.fileno())
        candidate.replace(path)
    finally:candidate.unlink(missing_ok=True)


def queue(directory):
    previous=status(directory)
    if previous.get('state') in ('queued','running'):return dict(ok=False,error='历史清空任务正在执行')
    job=secrets.token_hex(16)
    value=dict(id=job,state='queued',phase='等待开始',started=time.time(),finished=0,error='')
    save(directory,value)
    try:
        subprocess.run(['systemd-run','--quiet','--collect','--unit=ips-history-reset-'+job[:12],
            '--on-active=2s','--timer-property=AccuracySec=1s','--timer-property=RemainAfterElapse=no',
            '/usr/bin/python3','-B',str(Path(__file__).resolve()),'--run','--job',job,'--state-dir',str(Path(directory).resolve())],
            check=True,capture_output=True,text=True,timeout=10)
    except Exception:
        save(directory,dict(value,state='failed',phase='未开始',finished=time.time(),error='无法启动历史清空任务'))
        raise
    return dict(ok=True,pending=True,reset_id=job)


def command(*args):
    return subprocess.run(list(args),check=True,capture_output=True,text=True,timeout=150)


def active(unit):
    return subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0


def stop(unit):
    command('systemctl','stop',unit)
    if command('systemctl','show',unit,'-p','MainPID','--value').stdout.strip()!='0':
        raise RuntimeError('服务未完全停止：'+unit)


def web_ready():
    config=json.loads(CONFIG.read_text())
    host=config.get('bind') or '127.0.0.1'
    if host in ('0.0.0.0','::'):host='127.0.0.1'
    if ':' in host:host='['+host+']'
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://'+host+':'+str(config.get('port',9000))+'/healthz',timeout=2) as response:
        return response.status==200 and json.load(response).get('ok') is True


def remove_history_files(database):
    database=Path(database)
    if database.name!='snort-ndr.db' or database.resolve().parent!=WEB_STATE.resolve():
        raise ValueError('Unexpected event database path')
    # All writers must already be stopped. Only the event store and its derived
    # projection are removed; settings and every other state file stay in place.
    targets=[Path(str(database)+suffix) for suffix in ('','-wal','-shm','.summary.db','.summary.db-wal','.summary.db-shm')]
    for path in targets:
        if path.is_symlink() or path.resolve().parent!=WEB_STATE.resolve():raise ValueError('Invalid database cleanup target')
    logs=[];directories=[]
    for root,pattern in ((NATIVE,NATIVE_NAMES),(STREAM.parent,STREAM_NAMES)):
        for path in root.iterdir():
            if not pattern.fullmatch(path.name):continue
            if path.is_symlink() or not path.is_file() or path.resolve().parent!=root.resolve():raise ValueError('Invalid event log cleanup target')
            logs.append(path)
    for directory in NATIVE.iterdir():
        if not ARCHIVE_NAME.fullmatch(directory.name):continue
        if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent!=NATIVE.resolve():raise ValueError('Invalid native archive directory')
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file() or not NATIVE_NAMES.fullmatch(path.name):raise ValueError('Invalid native archive member')
            logs.append(path)
        directories.append(directory)
    if CHECKPOINT.is_symlink() or (CHECKPOINT.exists() and not CHECKPOINT.is_file()):raise ValueError('Invalid checkpoint cleanup target')
    for path in logs:path.unlink()
    for path in directories:path.rmdir()
    for path in targets:path.unlink(missing_ok=True)
    CHECKPOINT.unlink(missing_ok=True)
    # The bridge opens its stream on every poll; let it recreate the file using
    # the same access mode as the running installation.


def run(directory,job):
    value=status(directory)
    if not re.fullmatch('[0-9a-f]{32}',job) or value.get('id')!=job or value.get('state')!='queued':
        raise ValueError('Invalid or already executed reset job')
    from ips_control import Client
    client=Client(timeout=10)
    timers=[];acquired=False;stopping=False
    def phase(text):
        value.update(state='running',phase=text);save(directory,value)
    try:
        maintenance=client.request('history-reset-begin',job=job)
        if not maintenance.get('ok'):raise RuntimeError(maintenance.get('error','规则任务正在执行'))
        acquired=True
        timers=[unit for unit in ('ips-log-maintenance.timer','snort-home-net.timer') if active(unit)]
        stream_info=STREAM.stat() if STREAM.exists() else None
        for unit in timers:command('systemctl','stop',unit)
        command('systemctl','stop','ips-log-maintenance.service','snort-home-net.service')
        phase('停止检测和采集')
        # SIGSTOP would leave NFQUEUE listeners alive and fill their queues.
        # Orderly service stop closes listeners and removes the queue table.
        stopping=True;stop('ips');stop('ips-event-bridge');stop('ips-web')
        phase('清空事件和未入库日志')
        remove_history_files(WEB_STATE/'snort-ndr.db')
        STREAM.touch()
        if stream_info:
            os.chmod(STREAM,stream_info.st_mode&0o777);os.chown(STREAM,stream_info.st_uid,stream_info.st_gid)
        else:os.chmod(STREAM,0o644)
        phase('重新启动检测和采集')
        command('systemctl','start','ips')
        command('systemctl','start','ips-event-bridge','ips-web')
        from snort_engine import SnortControl
        deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            try:
                SnortControl().command('show_config_generation()',timeout=2)
                if active('ips-web') and active('ips-event-bridge') and web_ready():break
            except (OSError,RuntimeError,TimeoutError):pass
            time.sleep(.5)
        else:raise RuntimeError('重启后服务未就绪')
        value.update(state='done',phase='已清空并恢复采集',finished=time.time(),error='');save(directory,value)
    except Exception as exc:
        value.update(state='failed',phase='清空或重启失败',finished=time.time(),error=str(exc));save(directory,value)
        # Restore service availability without pretending discarded history can
        # be rolled back. The persisted status records any failure.
        if stopping:subprocess.run(['systemctl','start','ips','ips-event-bridge','ips-web'],capture_output=True,timeout=150)
        raise
    finally:
        try:
            for unit in timers:command('systemctl','start',unit)
        finally:
            if acquired:client.request('history-reset-finish',job=job)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--job',required=True)
    parser.add_argument('--state-dir',type=Path,default=STATE)
    args=parser.parse_args()
    if os.geteuid()!=0 or not args.run:raise SystemExit('Run as root for an explicitly queued reset')
    if args.state_dir.resolve()!=STATE.resolve():raise SystemExit('Unexpected reset state directory')
    run(args.state_dir,args.job)


if __name__=='__main__':main()
