"""Deployment-only clients and filesystem checks for the Go services.

No daemon, event parser, database, rule policy or application logic lives here.
"""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import threading
import time

PREFIX=os.environ.get('SNORT_ENGINE_PREFIX','/opt/ips-snort3/3.12.4.0')
BINARY=PREFIX+'/bin/snort'
CONFIG='/etc/snort/snort.lua'
SOCKET='/run/snort/control.sock'
RECEIPT=Path('/etc/ips-session-logger.json')
LIBRARY_ROOT=Path(PREFIX)/'lib/ndr'
MARKER=Path('/run/ips-rule-manager/session-logger-loaded.json')
LOG_MARKER=Path('/etc/ips-log-storage.json')
ROOT=Path('/var/lib/ips-snort-logs')
_configuration_gate=threading.RLock()


class Client:
    def __init__(self,path='/run/ips-rule-manager/control.sock',timeout=70):
        self.path,self.timeout=path,timeout

    def request(self,operation,**parameters):
        data=json.dumps(dict(operation=operation,**parameters),ensure_ascii=False).encode()+b'\n'
        if len(data)>256*1024:raise ValueError('Control request exceeds limit')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.settimeout(self.timeout);channel.connect(self.path);channel.sendall(data)
            with channel.makefile('rb') as stream:reply=stream.readline(16*1024*1024+1)
        if len(reply)>16*1024*1024 or not reply.endswith(b'\n'):raise ValueError('Invalid control response')
        value=json.loads(reply)
        if not value.get('ok'):raise RuntimeError(value.get('error','Go rule manager unavailable'))
        return value['result']


@contextmanager
def configuration_lock(config=CONFIG,*,blocking=True):
    if not _configuration_gate.acquire(blocking=blocking):raise BlockingIOError(errno.EAGAIN,'Configuration is busy')
    try:
        try:import fcntl
        except ImportError:
            yield;return
        descriptor=os.open(Path(config).with_name('.configuration.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,'a') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|(0 if blocking else fcntl.LOCK_NB))
            try:yield
            finally:fcntl.flock(handle,fcntl.LOCK_UN)
    finally:_configuration_gate.release()


class SnortControl:
    def __init__(self,path=SOCKET):self.path=path

    def command(self,command,timeout=10):
        deadline=time.monotonic()+timeout
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.settimeout(min(2,timeout));channel.connect(self.path)
            def read():
                output=bytearray()
                while time.monotonic()<deadline:
                    channel.settimeout(max(.01,deadline-time.monotonic()));chunk=channel.recv(65536)
                    if not chunk:raise RuntimeError('Engine control channel closed')
                    output.extend(chunk)
                    if len(output)>8*1024*1024:raise ValueError('Engine control response exceeds limit')
                    if b'o")~ ' in output:return output.decode('utf-8','replace')
                raise TimeoutError('Engine control deadline exceeded')
            read();channel.sendall(command.encode('ascii')+b'\n');return read()

    def call(self,commands,timeout=10):
        result={}
        try:
            for command in commands:
                if command!='ruleset-reload-rules':raise ValueError('Unsupported deployment operation')
                before=self.command('show_config_generation()',timeout)
                reply=self.command('reload_config()',timeout)
                if re.search('fail|error|restart required',reply,re.I):raise RuntimeError('Engine rejected reload')
                deadline=time.monotonic()+timeout
                while time.monotonic()<deadline:
                    if self.command('show_config_generation()',min(5,timeout))!=before:
                        result[command]={'confirmed':True};break
                    time.sleep(.2)
                else:raise TimeoutError('Engine configuration did not advance')
        except (OSError,ValueError,RuntimeError,TimeoutError) as error:result['__error__']=str(error)
        return result


def plugin_arguments(receipt=RECEIPT):
    receipt=Path(receipt)
    if not receipt.exists():return []
    digest=json.loads(receipt.read_text()).get('sha256','')
    if not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Invalid extension receipt')
    library=LIBRARY_ROOT/digest/'ndr_session.so'
    if library.is_symlink() or not library.is_file() or hashlib.sha256(library.read_bytes()).hexdigest()!=digest:
        raise ValueError('Extension checksum differs')
    return ['--plugin-path',str(library)]


def process_key():
    pid=int(Path('/run/snort/snort.pid').read_text())
    return [pid,Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19],Path('/proc/sys/kernel/random/boot_id').read_text().strip()]


def mark_loaded():
    value=dict(process=process_key(),sha256=json.loads(RECEIPT.read_text())['sha256'])
    temporary=MARKER.with_suffix('.new');temporary.write_text(json.dumps(value)+'\n');temporary.replace(MARKER)


def reload_extension(control,config):
    arguments=plugin_arguments()
    if not arguments:return
    before=control.command('show_config_generation()',timeout=5)
    reply=control.command('snort.reload_config('+json.dumps(str(config))+','+json.dumps(arguments[1])+')',timeout=300)
    if re.search('failed|restart required|bad config|error:',reply,re.I):raise RuntimeError('Extension reload failed')
    deadline=time.monotonic()+60
    while control.command('show_config_generation()',timeout=5)==before:
        if time.monotonic()>=deadline:raise TimeoutError('Extension configuration did not advance')
        time.sleep(.1)
    mark_loaded()


def log_configuration():
    if not LOG_MARKER.exists():return {}
    if LOG_MARKER.is_symlink():raise ValueError('Log marker cannot be a symlink')
    value=json.loads(LOG_MARKER.read_text())
    if value.get('root')!=str(ROOT):raise ValueError('Unexpected persistent log root')
    return value


def log_paths():
    configured=os.environ.get('IPS_LOG_STORAGE_ROOT')
    if configured:
        if configured!=str(ROOT):raise ValueError('Unexpected service log root')
        return ROOT/'snort',ROOT/'events/events.json'
    if log_configuration().get('direct_paths'):return ROOT/'snort',ROOT/'events/events.json'
    return Path('/var/log/snort'),Path('/var/log/ips/events.json')


def validate_log_storage():
    config=log_configuration()
    if not config:return
    for alias,relative in ((Path('/var/log/snort'),'snort'),(Path('/var/log/ips'),'events')):
        target=ROOT/relative
        if target.is_symlink() or not target.is_dir():raise ValueError('Persistent log directory is unavailable')
        if not config.get('direct_paths') and (alias.is_symlink() or not alias.is_dir() or not os.path.samefile(alias,target)):
            raise ValueError('Persistent log binding is unavailable')

# Exact obsolete files retired only after a verified Go installation; backups remain.
LEGACY_COMPONENTS=('dns_context.py', 'event_processing.py', 'hunt_query.py', 'history_reset.py', 'llm_assistant.py', 'llm_hunting.py', 'native_rules.py', 'openappid_update.py', 'overview_metrics.py', 'parallel_cpu.py', 'parallel_sql.py', 'rule_drafts.py', 'rule_identity.py', 'rule_inventory.py', 'rule_policy.py', 'rule_sources.py', 'runtime_status.py', 'session_logger.py', 'snort_engine.py', 'snort_rules.py', 'quic_observer.py', 'python_dependencies.py', 'ips_control.py', 'log_storage.py', 'recover-event-db.py', 'python-dependencies.zip')
