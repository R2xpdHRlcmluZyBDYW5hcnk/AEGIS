"""Update the console runtime without replacing or restarting the engine."""
import datetime
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import struct
import time
from ips_control import Client
from deployment_layout import layout

PROGRAMS=('ips-web','ips-rule-manager','ips_control.py','rule_drafts.py','llm_assistant.py','quic_observer.py','dns_context.py','llm_hunting.py','overview_metrics.py','hunt_query.py','python_dependencies.py','python-dependencies.zip','openappid_update.py','session_logger.py','snort_engine.py',
          'snort_rules.py','rule_policy.py','parallel_cpu.py','parallel_sql.py','event_processing.py','native_rules.py','rule_sources.py','rule_identity.py','rule_inventory.py','runtime_status.py','history_reset.py','log_storage.py','ips-event-bridge','ips-snort-rules','snort-home-net','deployment_layout.py')
CONFIG=Path(layout()['config'])
BIN=Path(layout()['program_dir'])
BACKUPS=Path('/var/backups/ips-console')
SERVICES=('ips-web','ips-rule-manager','ips-event-bridge')
SHARED_CONSOLE_PROGRAMS=frozenset(('ips_control.py','runtime_status.py'))
WEB_PROGRAMS=frozenset(('ips-web','llm_assistant.py','dns_context.py','llm_hunting.py',
                       'overview_metrics.py','hunt_query.py','python_dependencies.py','python-dependencies.zip','libsqlite3-ndr.so')) | SHARED_CONSOLE_PROGRAMS
MANAGER_PROGRAMS=frozenset(('openappid_update.py','history_reset.py')) | SHARED_CONSOLE_PROGRAMS
NATIVE_PROGRAMS=frozenset(('ips-web','ips-rule-manager','ips-event-bridge','ips-snort-rules'))
PIDFILE=Path('/run/snort/snort.pid')
RESOURCE_ROOT=Path('/etc/systemd/system')
RESOURCE_OVERRIDES={
    'ips-web.service':b'[Service]\nCPUQuota=400%\n',
    'ips-event-bridge.service':b'[Service]\nCPUQuota=400%\nMemoryMax=256M\n',
    'ips-rule-manager.service':b'[Service]\nTasksMax=64\nCPUQuota=400%\n',
}


def wait_manager():
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        try:
            if Client(timeout=2).request('ping').get('ready'):return
        except (OSError,ValueError,RuntimeError):pass
        time.sleep(.1)
    raise RuntimeError('Rule manager control socket did not become ready')


def validate_sqlite_runtime(path):
    code = '''import ctypes, sys
library = ctypes.CDLL(sys.argv[1], mode=ctypes.RTLD_GLOBAL)
library.sqlite3_libversion.restype = ctypes.c_char_p
import sqlite3
if sqlite3.sqlite_version != library.sqlite3_libversion().decode() or sqlite3.sqlite_version_info < (3, 51, 3):
    raise SystemExit('Console SQLite runtime is incompatible or lacks the WAL fix')
print(sqlite3.sqlite_version)
'''
    return subprocess.check_output([sys.executable, '-B', '-c', code, str(path.resolve())], text=True).strip()


def validate_native_release(release, *, execute=True):
    release=Path(release)
    manifest=json.loads((release/'backend-build.json').read_text())
    if (manifest.get('schema')!=1 or manifest.get('backend')!='go' or manifest.get('target')!='linux-arm64'
            or set(manifest.get('files',{}))!=NATIVE_PROGRAMS):
        raise ValueError('Invalid native backend manifest')
    for name,expected in manifest['files'].items():
        data=(release/name).read_bytes()
        if (len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=183
                or hashlib.sha256(data).hexdigest()!=expected):
            raise ValueError('Native backend executable verification failed: '+name)
    if execute:
        if platform.machine() not in ('aarch64','arm64'):raise ValueError('Native console deployment requires ARM64')
        info=json.loads(subprocess.check_output([str((release/'ips-web').resolve()),'--version'],text=True,timeout=10))
        if (info.get('backend')!='go' or info.get('go_version')!='go'+manifest['go_version']
                or info.get('sqlite_version')!=manifest['sqlite_version'] or info.get('target')!=manifest['target']):
            raise ValueError('Native backend runtime differs from manifest')
    return manifest


def apply(release,wait_ready,overrides,snapshot=None):
    release=Path(release)
    native=validate_native_release(release) if (release/'backend-build.json').is_file() else None
    runtime = release/'libsqlite3-ndr.so'
    sqlite_version = native['sqlite_version'] if native else validate_sqlite_runtime(runtime) if runtime.is_file() else None
    programs = PROGRAMS + (('backend-build.json',) if native else (runtime.name,) if sqlite_version else ())
    for name in PROGRAMS:
        if native and name in NATIVE_PROGRAMS:continue
        if name.endswith('.zip'):
            import zipfile
            with zipfile.ZipFile(release/name) as bundle:
                if bundle.testzip() or 'luqum/parser.py' not in bundle.namelist():raise ValueError('Invalid Python dependency bundle')
        else:compile((release/name).read_bytes(),name,'exec')
    original=CONFIG.read_bytes();config=json.loads(original)
    updated=dict(config,**overrides)
    changed=[name for name in programs if not (BIN/name).exists() or (BIN/name).read_bytes()!=(release/name).read_bytes()]
    resources={RESOURCE_ROOT/(name+'.d')/'50-ips-parallel.conf':data for name,data in RESOURCE_OVERRIDES.items()}
    resource_before={path:path.read_bytes() if path.exists() else None for path in resources}
    resources_changed=any(resource_before[path]!=data for path,data in resources.items())
    if not changed and updated==config and not resources_changed:
        print(json.dumps({'backend_unchanged':True}));return
    changed_set = set(changed)
    if changed_set <= WEB_PROGRAMS | MANAGER_PROGRAMS and not resources_changed:
        services = tuple(name for name,needed in (
            ('ips-web', updated!=config or bool(changed_set & WEB_PROGRAMS)),
            ('ips-rule-manager', bool(changed_set & MANAGER_PROGRAMS))) if needed)
    else:
        services = SERVICES
    start_services=[name for name in reversed(SERVICES) if name in services]
    engine_pid=PIDFILE.read_text() if PIDFILE.exists() else None
    client=Client()
    paused=client.request('maintenance',enabled=True)
    if not paused.get('ok'):
        raise RuntimeError(paused.get('error','Cannot pause rule jobs'))
    try:
        before=snapshot(config) if snapshot else None
        token=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup=BACKUPS/token;backup.mkdir(parents=True,mode=0o700)
        for name in programs:
            if (BIN/name).exists(): shutil.copy2(BIN/name,backup/name)
        (backup/'ips-web.conf').write_bytes(original)
        os.chmod(backup/'ips-web.conf',0o600)
        for index,(path,data) in enumerate(resource_before.items()):
            if data is not None:(backup/('resource-before-'+str(index))).write_bytes(data)
        (backup/'resources.json').write_text(json.dumps({str(path):'resource-before-'+str(index) if data is not None else None
            for index,(path,data) in enumerate(resource_before.items())},indent=2)+'\n')
        def install(source,target,mode):
            temporary=target.with_name(target.name+'.ips-new')
            try:
                shutil.copy2(source,temporary);os.chmod(temporary,mode);temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        try:
            subprocess.run(['systemctl','stop',*services],check=True)
            if CONFIG.read_bytes()!=original:
                raise RuntimeError('Configuration changed during update')
            for name in changed:
                install(release/name,BIN/name,0o644 if name.endswith(('.py','.zip','.so','.json')) else 0o755)
            if resources_changed:
                for index,(path,data) in enumerate(resources.items()):
                    path.parent.mkdir(parents=True,exist_ok=True)
                    candidate=backup/('resource-after-'+str(index));candidate.write_bytes(data)
                    install(candidate,path,0o644)
            if resources_changed:subprocess.run(['systemctl','daemon-reload'],check=True)
            if updated!=config:
                candidate=backup/'ips-web.new.conf'
                candidate.write_text(json.dumps(updated,indent=2)+'\n')
                install(candidate,CONFIG,0o600)
                candidate.unlink()
            subprocess.run(['systemctl','start',*start_services],check=True)
            health = wait_ready(updated)
            if sqlite_version and health.get('sqlite_version') != sqlite_version:
                raise RuntimeError('The restarted console did not select the installed SQLite runtime')
            if native and (health.get('backend')!='go' or health.get('go_version')!='go'+native['go_version']):
                raise RuntimeError('The restarted console did not select the native Go backend')
            wait_manager()
            if native:subprocess.run(['systemctl','is-active','--quiet',*services],check=True)
            if (PIDFILE.read_text() if PIDFILE.exists() else None)!=engine_pid:
                raise RuntimeError('Detection process changed during console update')
            for name in programs:
                if (BIN/name).read_bytes()!=(release/name).read_bytes():
                    raise RuntimeError('Console module verification failed')
            if any(path.read_bytes()!=data for path,data in resources.items()):raise RuntimeError('Parallel resource limits differ')
            if json.loads(CONFIG.read_bytes())!=updated:
                raise RuntimeError('Unexpected console configuration change')
            if snapshot:
                after=snapshot(updated)
                for name,digest in before['files'].items():
                    if name not in (str(CONFIG),str(BIN/'ips-web')) and after['files'].get(name)!=digest:
                        raise RuntimeError('Protected file changed during console update: '+name)
                for key in ('db_inode','engine_pid','supervisor_pid','crontab'):
                    if before[key]!=after[key]:
                        raise RuntimeError('Protected runtime state changed: '+key)
        except BaseException:
            subprocess.run(['systemctl','stop',*services],check=False)
            for name in changed:
                if (backup/name).exists(): install(backup/name,BIN/name,0o644 if name.endswith(('.py','.zip','.so','.json')) else 0o755)
                elif (BIN/name).exists(): (BIN/name).unlink()
            if updated!=config:install(backup/'ips-web.conf',CONFIG,0o600)
            if resources_changed:
                for index,(path,data) in enumerate(resource_before.items()):
                    if data is None:path.unlink(missing_ok=True)
                    else:install(backup/('resource-before-'+str(index)),path,0o644)
            if resources_changed:subprocess.run(['systemctl','daemon-reload'],check=False)
            subprocess.run(['systemctl','start',*start_services],check=False)
            wait_ready(config)
            wait_manager()
            raise
        print(json.dumps({'backend_updated':True,'backup':str(backup),'engine_preserved':True,'services_restarted':services}))

    finally:
        client.request('maintenance',enabled=False)
