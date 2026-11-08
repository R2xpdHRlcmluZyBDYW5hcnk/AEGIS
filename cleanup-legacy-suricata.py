#!/usr/bin/env python3
"""Remove the retired Suricata installation after native Snort health checks."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from deployment_layout import layout

PROGRAMS=('ips-web','ips-supervisor','ips-rule-manager','deployment_support.py','deployment_layout.py')
UNITS=('ips-legacy.service','ips-web-legacy.service','ips-rule-manager-legacy.service',
       'ips-log-maintenance-legacy.service','ips-log-maintenance-legacy.timer',
       'suricata-home-net.service','suricata-home-net.timer','suricata.service','var-log-suricata.mount')
TREES=('/etc/suricata','/var/lib/suricata','/var/log/suricata','/run/suricata',
       '/var/lib/ips-web','/var/lib/private/ips-web','/var/lib/ips-rule-manager',
       '/usr/local/share/ips-web','/etc/ips-legacy')
PACKAGES=('suricata','suricata-update')
MARKER=Path('/etc/ips-snort-deployment.json')


def command(*args,check=True):
    env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l') if args[0]=='apt-get' else None
    return subprocess.run(args,check=check,capture_output=True,text=True,env=env)


def protected_paths(config):
    return [Path(p).resolve() for p in ('/opt/ips-console','/opt/ips-snort3','/opt/ips-pulledpork3',
        '/etc/snort','/var/lib/snort','/var/lib/ips-snort-web','/var/lib/ips-snort-rule-manager',
        '/var/lib/ips-snort-logs','/var/log/snort','/var/log/ips','/run/snort','/run/ips-rule-manager',
        '/usr/local/share/ips-snort-web','/etc/ips-snort-web.conf',config['event_db'])]


def validate_target(path,protected):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or path==Path('/'):
        raise ValueError('Invalid cleanup path')
    resolved=path.resolve()
    for keep in protected:
        if resolved==keep or resolved in keep.parents or keep in resolved.parents:
            raise ValueError('Cleanup overlaps current Snort installation: '+str(path))
    if path.is_dir() and not path.is_symlink():
        if os.path.ismount(path):raise ValueError('Unmount legacy storage before deletion: '+str(path))
        for root,dirs,_ in os.walk(path,followlinks=False):
            for name in dirs:
                child=Path(root)/name
                if not child.is_symlink() and os.path.ismount(child):
                    raise ValueError('Nested mount in cleanup target: '+str(child))
    return path


def legacy_backup(path):
    text=[]
    for name in ('verification.json','state.before.json'):
        source=path/name
        if source.is_file() and source.stat().st_size<=4<<20:
            text.append(source.read_text(errors='replace'))
    content='\n'.join(text)
    if any(p in content for p in ('/etc/snort','/opt/ips-console','/usr/local/share/ips-snort-web')):
        return False
    if any(p in content for p in ('/etc/suricata','/etc/ips-web.conf','/usr/local/bin/ips-web','/usr/local/share/ips-web')):
        return True
    for name in ('ips-web-before','ips-web.before'):
        source=path/name
        if source.is_file():
            with source.open('rb') as handle:
                if b'Suricata' in handle.read(16384):return True
    return False


def plan(config):
    paths=[Path('/usr/local/bin')/name for name in PROGRAMS]
    paths += [Path(p) for p in TREES]
    paths += [Path('/etc/ips-web.conf'),Path('/etc/logrotate.d/suricata'),
              Path('/etc/systemd/system/nftables.service.d/ips-legacy-restore.conf.disabled')]
    for unit in UNITS:
        paths.extend((Path('/etc/systemd/system')/unit,Path('/etc/systemd/system')/(unit+'.d')))
    cache=Path('/usr/local/bin/__pycache__')
    if cache.is_dir():
        paths += [p for p in cache.iterdir() if re.fullmatch(r'(ips_control|rule_drafts)\.[A-Za-z0-9_-]+\.pyc',p.name)]
    for root in (Path('/var/backups/ips-console'),Path('/var/backups/ips-angular')):
        if root.is_dir():
            paths += [p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and legacy_backup(p)]
    root=Path('/var/backups/ips-snort3')
    if root.is_dir():
        paths += [p for p in root.iterdir() if p.is_dir() and not p.is_symlink()
                  and (p/'legacy-console.conf').is_file() and (p/'migration.json').is_file()]
    protected=protected_paths(config)
    # Mounted legacy log storage is validated again after it is stopped.
    selected=sorted(set(p for p in paths if p.exists() or p.is_symlink()),key=str)
    for path in selected:
        resolved=path.resolve()
        if any(resolved==keep or resolved in keep.parents or keep in resolved.parents for keep in protected):
            raise ValueError('Legacy path overlaps native installation: '+str(path))
    return selected


def remove(path,protected):
    path=validate_target(path,protected)
    if path.is_symlink():path.unlink()
    elif path.is_dir():shutil.rmtree(path)
    else:path.unlink(missing_ok=True)


def verify_native(config):
    for unit in ('ips','ips-web','ips-rule-manager','ips-event-bridge'):
        command('systemctl','is-active','--quiet',unit)
    pid=Path('/run/snort/snort.pid').read_text().strip()
    if str(Path('/proc',pid,'exe').resolve())!='/opt/ips-snort3/3.12.4.0/bin/snort':
        raise ValueError('Unexpected running detection binary')
    from deployment_support import Client
    if not Client(timeout=3).request('ping').get('ready'):raise RuntimeError('Rule manager unavailable')
    return pid


def apply(config,paths):
    pid=verify_native(config)
    # Package removal must not expand to libraries shared by Snort or the router.
    preview=command('apt-get','-s','purge',*PACKAGES).stdout
    removed=set(re.findall(r'^(?:Purg|Remv)\s+(\S+)',preview,re.M))
    if not removed<=set(PACKAGES):raise ValueError('Package purge would remove unrelated packages')
    protected=protected_paths(config)
    for unit in UNITS:
        command('systemctl','stop',unit,check=False)
        command('systemctl','disable',unit,check=False)
    # Refuse cleanup if any previous supervisor or detector remains alive.
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        try:args=(path/'cmdline').read_bytes().split(b'\0')
        except (OSError,PermissionError):continue
        if b'/usr/bin/suricata' in args or any(str(Path('/usr/local/bin')/p).encode() in args for p in PROGRAMS):
            raise RuntimeError('A legacy program is still running')
    command('apt-get','purge','--assume-yes',*PACKAGES)
    for path in paths:remove(path,protected)
    command('systemctl','daemon-reload')
    if verify_native(config)!=pid:raise RuntimeError('Native detector changed during legacy cleanup')
    marker=json.loads(MARKER.read_text())
    if Path(marker.get('backup','/nonexistent')) in paths:marker.pop('backup',None)
    marker['legacy_removed']=True
    marker['legacy_removed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    staged=MARKER.with_suffix('.new');staged.write_text(json.dumps(marker,indent=2)+'\n');staged.chmod(0o600);staged.replace(MARKER)
    print(json.dumps(dict(legacy_removed=True,packages=list(PACKAGES),paths_removed=len(paths),engine_preserved=True)))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run as root')
    current=layout()
    if current['program_dir']!='/opt/ips-console/bin':raise ValueError('Complete native Snort deployment first')
    config=json.loads(Path(current['config']).read_text())
    paths=plan(config)
    if not args.apply:
        print(json.dumps(dict(packages=list(PACKAGES),paths=[str(p) for p in paths]),indent=2));return
    import fcntl
    with open('/run/ips-deploy.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        apply(config,paths)


if __name__=='__main__':main()
