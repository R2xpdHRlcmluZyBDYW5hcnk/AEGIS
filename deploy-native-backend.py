"""Update interpreted console modules without replacing or restarting the engine."""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from ips_control import Client
from deployment_layout import layout

PROGRAMS=('ips-web','ips-rule-manager','ips_control.py','rule_drafts.py','snort_engine.py',
          'snort_rules.py','rule_policy.py','parallel_cpu.py','parallel_sql.py','event_processing.py','native_rules.py','rule_sources.py','rule_identity.py','rule_inventory.py','runtime_status.py','history_reset.py','log_storage.py','ips-event-bridge','ips-snort-rules','snort-home-net','deployment_layout.py')
CONFIG=Path(layout()['config'])
BIN=Path(layout()['program_dir'])
BACKUPS=Path('/var/backups/ips-console')
SERVICES=('ips-web','ips-rule-manager','ips-event-bridge')
PIDFILE=Path('/run/snort/snort.pid')
RESOURCE_ROOT=Path('/etc/systemd/system')
RESOURCE_OVERRIDES={
    'ips-event-bridge.service':b'[Service]\nCPUQuota=400%\nMemoryMax=256M\n',
    'ips-rule-manager.service':b'[Service]\nTasksMax=64\n',
}


def wait_manager():
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        try:
            if Client(timeout=2).request('ping').get('ready'):return
        except (OSError,ValueError,RuntimeError):pass
        time.sleep(.1)
    raise RuntimeError('Rule manager control socket did not become ready')


def apply(release,wait_ready,overrides,snapshot=None):
    release=Path(release)
    for name in PROGRAMS:
        compile((release/name).read_bytes(),name,'exec')
    original=CONFIG.read_bytes();config=json.loads(original)
    updated=dict(config,**overrides)
    changed=[name for name in PROGRAMS if not (BIN/name).exists() or (BIN/name).read_bytes()!=(release/name).read_bytes()]
    resources={RESOURCE_ROOT/(name+'.d')/'50-ips-parallel.conf':data for name,data in RESOURCE_OVERRIDES.items()}
    resource_before={path:path.read_bytes() if path.exists() else None for path in resources}
    resources_changed=any(resource_before[path]!=data for path,data in resources.items())
    if not changed and updated==config and not resources_changed:
        print(json.dumps({'backend_unchanged':True}));return
    engine_pid=PIDFILE.read_text() if PIDFILE.exists() else None
    client=Client()
    paused=client.request('maintenance',enabled=True)
    if not paused.get('ok'):
        raise RuntimeError(paused.get('error','Cannot pause rule jobs'))
    try:
        before=snapshot(config) if snapshot else None
        token=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup=BACKUPS/token;backup.mkdir(parents=True,mode=0o700)
        for name in PROGRAMS:
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
            subprocess.run(['systemctl','stop',*SERVICES],check=True)
            if CONFIG.read_bytes()!=original:
                raise RuntimeError('Configuration changed during update')
            for name in PROGRAMS:
                install(release/name,BIN/name,0o644 if name.endswith('.py') else 0o755)
            for index,(path,data) in enumerate(resources.items()):
                path.parent.mkdir(parents=True,exist_ok=True)
                candidate=backup/('resource-after-'+str(index));candidate.write_bytes(data)
                install(candidate,path,0o644)
            if resources_changed:subprocess.run(['systemctl','daemon-reload'],check=True)
            candidate=backup/'ips-web.new.conf'
            candidate.write_text(json.dumps(updated,indent=2)+'\n')
            install(candidate,CONFIG,0o600)
            candidate.unlink()
            subprocess.run(['systemctl','start','ips-event-bridge','ips-rule-manager','ips-web'],check=True)
            wait_ready(updated)
            wait_manager()
            if (PIDFILE.read_text() if PIDFILE.exists() else None)!=engine_pid:
                raise RuntimeError('Detection process changed during console update')
            for name in PROGRAMS:
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
            subprocess.run(['systemctl','stop',*SERVICES],check=False)
            for name in PROGRAMS:
                if (backup/name).exists(): install(backup/name,BIN/name,0o644 if name.endswith('.py') else 0o755)
                elif (BIN/name).exists(): (BIN/name).unlink()
            install(backup/'ips-web.conf',CONFIG,0o600)
            for index,(path,data) in enumerate(resource_before.items()):
                if data is None:path.unlink(missing_ok=True)
                else:install(backup/('resource-before-'+str(index)),path,0o644)
            if resources_changed:subprocess.run(['systemctl','daemon-reload'],check=False)
            subprocess.run(['systemctl','start','ips-event-bridge','ips-rule-manager','ips-web'],check=False)
            wait_ready(config)
            wait_manager()
            raise
        print(json.dumps({'backend_updated':True,'backup':str(backup),'engine_preserved':True}))

    finally:
        client.request('maintenance',enabled=False)
