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
from deployment_support import Client
from deployment_layout import layout

NATIVE_PROGRAMS=frozenset(('ips-web','ips-rule-manager','ips-event-bridge','ips-snort-rules'))
MAINTENANCE_PROGRAMS=frozenset(('snort-home-net','ips-quic-observer','ips-maintenance','recover-event-db'))
PROGRAMS=tuple(sorted(NATIVE_PROGRAMS|MAINTENANCE_PROGRAMS))+('deployment_support.py','deployment_layout.py')
CONFIG=Path(layout()['config'])
BIN=Path(layout()['program_dir'])
BACKUPS=Path('/var/backups/ips-console')
SERVICES=('ips-web','ips-rule-manager','ips-event-bridge')
WEB_PROGRAMS=frozenset(('ips-web',))
MANAGER_PROGRAMS=frozenset(('ips-rule-manager',))
TOOL_PROGRAMS=frozenset(('deployment_support.py','deployment_layout.py','ips-snort-rules','snort-home-net','ips-maintenance','recover-event-db','backend-build.json','maintenance-build.json'))
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


def validate_go_manifest(release, receipt, programs, *, execute=True):
    release=Path(release)
    manifest=json.loads((release/receipt).read_text())
    if (manifest.get('schema')!=1 or manifest.get('backend')!='go' or manifest.get('target')!='linux-arm64'
            or set(manifest.get('files',{}))!=set(programs)):
        raise ValueError('Invalid native backend manifest')
    for name,expected in manifest['files'].items():
        data=(release/name).read_bytes()
        if (len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=183
                or hashlib.sha256(data).hexdigest()!=expected):
            raise ValueError('Native backend executable verification failed: '+name)
    if execute:
        if platform.machine() not in ('aarch64','arm64'):raise ValueError('Native console deployment requires ARM64')
        entry=sorted(programs)[0]
        info=json.loads(subprocess.check_output([str((release/entry).resolve()),'--version'],text=True,timeout=10))
        if (info.get('backend')!='go' or info.get('go_version')!='go'+manifest['go_version']
                or info.get('sqlite_version')!=manifest['sqlite_version'] or info.get('target')!=manifest['target']):
            raise ValueError('Native backend runtime differs from manifest')
    return manifest


def validate_native_release(release, *, execute=True):
    return validate_go_manifest(release,'backend-build.json',NATIVE_PROGRAMS,execute=execute)


def apply(release,wait_ready,overrides,snapshot=None,reset_event_data=False,console_only=False):
    release=Path(release)
    native=validate_native_release(release)
    maintenance=validate_go_manifest(release,'maintenance-build.json',MAINTENANCE_PROGRAMS)
    sqlite_version=native['sqlite_version']
    programs=PROGRAMS+('backend-build.json','maintenance-build.json')
    for name in programs:
        if name.endswith('.py'):compile((release/name).read_bytes(),name,'exec')
    from deployment_support import LEGACY_COMPONENTS
    retired=[]
    for name in LEGACY_COMPONENTS:
        path=BIN/name
        if path.is_symlink():raise ValueError('Refusing linked obsolete component: '+name)
        if path.exists():
            if not path.is_file():raise ValueError('Unexpected obsolete component type: '+name)
            retired.append(name)
    cache=BIN/'__pycache__'
    if cache.is_symlink():raise ValueError('Refusing linked component cache')
    if cache.exists():
        if not cache.is_dir():raise ValueError('Unexpected component cache type')
        stems={Path(name).stem for name in LEGACY_COMPONENTS if name.endswith('.py')}
        for path in cache.glob('*.pyc'):
            if path.name.split('.',1)[0] not in stems:continue
            if path.is_symlink() or not path.is_file():raise ValueError('Unexpected obsolete cache entry')
            retired.append('__pycache__/'+path.name)
    original=CONFIG.read_bytes();config=json.loads(original)
    updated=dict(config,**overrides)
    changed=[name for name in programs if not (BIN/name).exists() or (BIN/name).read_bytes()!=(release/name).read_bytes()]
    resources={RESOURCE_ROOT/(name+'.d')/'50-ips-parallel.conf':data for name,data in RESOURCE_OVERRIDES.items()}
    # Existing service allocations belong to the administrator. Defaults apply
    # only on first installation; upgrades never reset an assigned CPU budget.
    resources={path:path.read_bytes() if path.exists() else data for path,data in resources.items()}
    resources[RESOURCE_ROOT/'ips-web.service.d'/'70-overview-snapshot.conf']=b'[Service]\nRuntimeDirectory=ips-web-overview\nRuntimeDirectoryMode=0700\n'
    observer_unit=RESOURCE_ROOT/'ips-quic-observer.service'
    observer_active=False
    if maintenance and observer_unit.is_file():
        previous=observer_unit.read_bytes()
        candidate=previous.replace(b'/usr/bin/python3 -B /opt/ips-console/bin/quic_observer.py',b'/opt/ips-console/bin/ips-quic-observer')
        if b'quic_observer.py' in candidate:raise ValueError('Unrecognized QUIC observer service entry')
        resources[observer_unit]=candidate
        observer_active=subprocess.run(['systemctl','is-active','--quiet','ips-quic-observer'],capture_output=True).returncode==0
    resource_before={path:path.read_bytes() if path.exists() else None for path in resources}
    resources_changed=any(resource_before[path]!=data for path,data in resources.items())
    if not changed and not retired and updated==config and not resources_changed and not reset_event_data:
        print(json.dumps({'backend_unchanged':True}));return
    changed_set = set(changed)
    if changed_set <= WEB_PROGRAMS | MANAGER_PROGRAMS | TOOL_PROGRAMS and not resources_changed:
        services = tuple(name for name,needed in (
            ('ips-web', updated!=config or bool(changed_set & WEB_PROGRAMS)),
            ('ips-rule-manager', bool(changed_set & MANAGER_PROGRAMS))) if needed)
    else:
        services = SERVICES
    if observer_active and (resources.get(observer_unit)!=resource_before.get(observer_unit) or 'ips-quic-observer' in changed_set):
        services=(*services,'ips-quic-observer')
    if reset_event_data or console_only:
        # This storage switch changes the console's persistence only. The
        # detector, bridge and manager keep their current processes alive.
        services=('ips-web',)
    start_services=[name for name in reversed(SERVICES) if name in services]+(['ips-quic-observer'] if 'ips-quic-observer' in services else [])
    engine_pid=PIDFILE.read_text() if PIDFILE.exists() else None
    client=Client()
    database_archive=None
    paused=client.request('maintenance',enabled=True)
    if not paused.get('ok'):
        raise RuntimeError(paused.get('error','Cannot pause rule jobs'))
    try:
        before=snapshot(config) if snapshot else None
        token=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup=BACKUPS/token;backup.mkdir(parents=True,mode=0o700)
        for name in programs:
            if (BIN/name).exists(): shutil.copy2(BIN/name,backup/name)
        for name in retired:
            (backup/name).parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(BIN/name,backup/name)
        (backup/'retired-components.json').write_text(json.dumps(retired)+'\n')
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
            if services:subprocess.run(['systemctl','stop',*services],check=True)
            if CONFIG.read_bytes()!=original:
                raise RuntimeError('Configuration changed during update')
            if reset_event_data:
                if not updated.get('database_url'):raise ValueError('PostgreSQL reset requires a configured database')
                # Detection and its logs continue. Start at the retained stream's
                # current boundary instead of replaying retired SQLite history.
                stream='/var/lib/ips-snort-logs/events/events.json' if Path('/etc/ips-log-storage.json').exists() else updated.get('eve','/var/log/ips/events.json')
                output=subprocess.check_output([str(release/'ips-maintenance'),'postgresql-reset',
                    '--database-url',updated['database_url'],'--stream',stream],text=True)
                database_archive=json.loads(output)['archive']
            for name in changed:
                install(release/name,BIN/name,0o644 if name.endswith(('.py','.zip','.so','.json')) else 0o755)
            if resources_changed:
                for index,(path,data) in enumerate(resources.items()):
                    if resource_before[path]==data:continue
                    path.parent.mkdir(parents=True,exist_ok=True)
                    candidate=backup/('resource-after-'+str(index));candidate.write_bytes(data)
                    install(candidate,path,0o644)
            if resources_changed:subprocess.run(['systemctl','daemon-reload'],check=True)
            if updated!=config:
                candidate=backup/'ips-web.new.conf'
                candidate.write_text(json.dumps(updated,indent=2)+'\n')
                install(candidate,CONFIG,0o600)
                candidate.unlink()
            if start_services:subprocess.run(['systemctl','start',*start_services],check=True)
            health = wait_ready(updated)
            if sqlite_version and health.get('sqlite_version') != sqlite_version:
                raise RuntimeError('The restarted console did not select the installed SQLite runtime')
            if native and (health.get('backend')!='go' or health.get('go_version')!='go'+native['go_version']):
                raise RuntimeError('The restarted console did not select the native Go backend')
            if updated.get('database_url') and (health.get('event_database')!='postgresql' or health.get('event_db_ready') is not True or health.get('wal_compression')!='zstd' or not health.get('timescaledb_version')):
                raise RuntimeError('The PostgreSQL event store, WAL compression or TimescaleDB is not ready')
            wait_manager()
            if services:subprocess.run(['systemctl','is-active','--quiet',*services],check=True)
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
                if config.get('database_url') and not reset_event_data and before.get('postgres_identity')!=after.get('postgres_identity'):
                    raise RuntimeError('PostgreSQL database identity changed during console update')
            for name in retired:(BIN/name).unlink()
        except BaseException:
            if services:subprocess.run(['systemctl','stop',*services],check=False)
            database_recovery_error=None
            if database_archive:
                try:
                    subprocess.run([str(release/'ips-maintenance'),'postgresql-reset','--database-url',updated['database_url'],
                        '--restore',database_archive],check=True)
                except BaseException as recovery_error:
                    database_recovery_error=recovery_error
            for name in retired:install(backup/name,BIN/name,0o644)
            for name in changed:
                if (backup/name).exists(): install(backup/name,BIN/name,0o644 if name.endswith(('.py','.zip','.so','.json')) else 0o755)
                elif (BIN/name).exists(): (BIN/name).unlink()
            if updated!=config:install(backup/'ips-web.conf',CONFIG,0o600)
            if resources_changed:
                for index,(path,data) in enumerate(resource_before.items()):
                    if data is None:path.unlink(missing_ok=True)
                    else:install(backup/('resource-before-'+str(index)),path,0o644)
            if resources_changed:subprocess.run(['systemctl','daemon-reload'],check=False)
            if database_recovery_error and config.get('database_url'):
                raise RuntimeError('Previous PostgreSQL schema remains sealed; automatic schema recovery failed, so the console stays stopped') from database_recovery_error
            if start_services:subprocess.run(['systemctl','start',*start_services],check=False)
            wait_ready(config)
            wait_manager()
            raise
        print(json.dumps({'backend_updated':True,'backup':str(backup),'engine_preserved':True,'services_restarted':services,'retired_components':len(retired),'event_database':'postgresql' if updated.get('database_url') else 'sqlite','database_archive':database_archive}))

    finally:
        client.request('maintenance',enabled=False)
