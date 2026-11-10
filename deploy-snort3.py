#!/usr/bin/env python3
"""Explicit ARM64 engine activation with a fresh event-store path and rollback."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import socket
import secrets

PREFIX=Path('/opt/ips-snort3/3.12.4.0')
STATE=Path('/var/lib/ips-deploy')
BACKUPS=Path('/var/backups/ips-snort3')
CONFIG=Path('/etc/ips-web.conf')
NEW_CONFIG=Path('/etc/ips-snort-web.conf')
PROGRAM_DIR=Path('/opt/ips-console/bin')
STATIC_DIR=Path('/usr/local/share/ips-snort-web')
LAYOUT=Path('/etc/ips-snort-deployment.json')
PROGRAMS=('ips-web','ips-supervisor','ips-rule-manager','ips-event-bridge','ips-snort-rules','ips-log-maintenance','deployment_support.py','deployment_layout.py','snort-home-net')
UNITS=('ips.service','ips-web.service','ips-rule-manager.service','ips-event-bridge.service',
       'snort-home-net.service','snort-home-net.timer','ips-log-maintenance.service','ips-log-maintenance.timer')
ACTIVE_UNITS=('ips-web','ips-rule-manager','ips-event-bridge','ips')
DEPENDENCIES=('libdumbnet1','libhwloc15','libluajit-5.1-2','libpcap0.8t64','libpcre2-8-0',
              'libssl3t64','liblzma5','zlib1g','libmnl0','libunwind8','libnuma1','libuuid1',
              'libbrotli1','libstdc++6','nftables','logrotate')


def run(*args,check=True):
    return subprocess.run(args,check=check,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)


def engine_members(package):
    """Only the fixed engine tree is allowed; no external links or devices."""
    members=package.getmembers()
    for item in members:
        name=PurePosixPath(item.name)
        valid=(str(name).startswith('opt/ips-snort3/3.12.4.0/') or str(name)=='ENGINE_SHA256SUMS.json')
        if not valid or name.is_absolute() or '..' in name.parts or not (item.isfile() or item.issym() or item.isdir()):
            raise ValueError('Unexpected runtime archive member')
        if item.issym():
            target=PurePosixPath(item.linkname)
            if target.is_absolute() or '..' in target.parts:
                raise ValueError('Unexpected runtime symlink target')
    return members


def unpack_engine(archive,root):
    root=Path(root).resolve()
    with tarfile.open(archive) as package:
        members=engine_members(package)
        package.extractall(root,members=members,filter='data')
    sums=json.loads((root/'ENGINE_SHA256SUMS.json').read_text())
    expected={item.name for item in members if item.isfile() and item.name!='ENGINE_SHA256SUMS.json'}
    if set(sums)!=expected:
        raise ValueError('Runtime checksum inventory differs')
    for name,digest in sums.items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Runtime file checksum differs')
    manifest=json.loads((root/str(PREFIX).lstrip('/')/'engine-manifest.json').read_text())
    binary_name=str(PREFIX/'bin/snort').lstrip('/')
    if manifest['architecture']!='aarch64' or manifest['sha256']!=sums[binary_name]:
        raise ValueError('Runtime architecture differs')
    return sums


def console_configuration(original):
    config=dict(original)
    config.update(eve='/var/log/ips/events.json',event_db='/var/lib/ips-snort-web/snort-ndr.db',
                  port=9000,static_dir=STATIC_DIR.as_posix(),
                  rule_manager_socket='/run/ips-rule-manager/control.sock')
    return config


def install_file(source,target,mode=0o644):
    target=Path(target)
    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
        raise ValueError('Refusing managed destination symlink')
    target.parent.mkdir(parents=True,exist_ok=True)
    candidate=target.with_name(target.name+'.ips-new')
    try:
        shutil.copy2(source,candidate)
        os.chmod(candidate,mode)
        candidate.replace(target)
    finally:
        candidate.unlink(missing_ok=True)


LEGACY_UNITS=('ips-web','ips-rule-manager','ips','ips-log-maintenance.timer',
              'ips-log-maintenance.service','suricata-home-net.timer','suricata-home-net.service')
RENAMED_UNITS={'ips.service':'ips-legacy.service','ips-web.service':'ips-web-legacy.service',
               'ips-rule-manager.service':'ips-rule-manager-legacy.service',
               'ips-log-maintenance.service':'ips-log-maintenance-legacy.service',
               'ips-log-maintenance.timer':'ips-log-maintenance-legacy.timer'}


def private_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.new')
    try:
        with temporary.open('w') as handle:
            os.chmod(temporary,0o600);json.dump(value,handle,indent=2)
            handle.flush();os.fsync(handle.fileno())
        temporary.replace(path)
    finally: temporary.unlink(missing_ok=True)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def old_data_metadata():
    result={}
    # Metadata only. Never query, duplicate or rebuild the old database.
    for directory in (Path('/var/lib/ips-web'),Path('/var/lib/ips-rule-manager')):
        if not directory.exists(): continue
        for path in directory.rglob('*'):
            if path.is_file():
                stat=path.stat()
                result[str(path)]=[stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns]
    return result


def render_unit(name,text):
    text=text.replace('/usr/local/bin/',PROGRAM_DIR.as_posix()+'/')
    text=text.replace('/etc/ips-web.conf',NEW_CONFIG.as_posix())
    text=text.replace('StateDirectory=ips-web\n','StateDirectory=ips-snort-web\n')
    text=text.replace('StateDirectory=ips-rule-manager\n','StateDirectory=ips-snort-rule-manager\n')
    text=text.replace('/var/lib/private/ips-web','/var/lib/private/ips-snort-web')
    text=text.replace('/var/lib/ips-rule-manager','/var/lib/ips-snort-rule-manager')
    if '[Service]\n' in text:
        text=text.replace('[Service]\n','[Service]\nEnvironment=IPS_PROGRAM_DIRECTORY='+PROGRAM_DIR.as_posix()+'\n',1)
    if name=='ips.service':
        text=text.replace('Conflicts=snort.service','Conflicts=snort.service ips-legacy.service')
    return text


def pause_legacy_manager():
    path='/run/ips-rule-manager/control.sock'
    if not Path(path).exists(): return
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(10);channel.connect(path)
        channel.sendall(b'{"operation":"maintenance","enabled":true}\n')
        with channel.makefile('rb') as reader: response=json.loads(reader.readline(262144))
    result=response.get('result',{})
    if not response.get('ok') or not result.get('ok'):
        raise RuntimeError('Legacy rule manager has a running task; no engine switch was made')


def rollback(backup):
    backup=Path(backup).resolve()
    if backup.parent!=BACKUPS.resolve() or backup.is_symlink():
        raise ValueError('Unexpected rollback directory')
    manifest=json.loads((backup/'migration.json').read_text())
    for unit in ('snort-home-net.timer','ips-log-maintenance.timer',*ACTIVE_UNITS):
        run('systemctl','stop',unit,check=False)
        run('systemctl','disable',unit,check=False)
    displaced=backup/'native-units';displaced.mkdir(exist_ok=True)
    for index,entry in reversed(list(enumerate(manifest['moves']))):
        original,archived=map(Path,entry)
        if not archived.exists(): continue
        if original.exists() or original.is_symlink(): original.rename(displaced/str(index))
        archived.rename(original)
    if LAYOUT.exists(): LAYOUT.rename(backup/'native-layout.failed.json')
    rotation=Path('/etc/logrotate.d/ips-snort')
    if rotation.exists(): rotation.rename(backup/'native-logrotate.failed')
    run('systemctl','daemon-reload')
    for unit,enabled in manifest['enabled'].items():
        if enabled: run('systemctl','enable',unit)
    for unit in ('ips','ips-rule-manager','ips-web','ips-log-maintenance.timer','suricata-home-net.timer'):
        if manifest['active'].get(unit): run('systemctl','start',unit)
    if digest(CONFIG)!=manifest['preserved'][str(CONFIG)]:
        raise RuntimeError('Original console configuration changed')
    print('Legacy services restored; native programs and data retained: '+str(backup))


def activate(release,engine_archive):
    if os.geteuid()!=0 or platform.machine() not in ('aarch64','arm64'):
        raise ValueError('Activation requires the ARM64 target and root')
    if LAYOUT.exists():
        raise ValueError('Native console is already installed; use a backend/static update')
    release=Path(release).resolve()
    for name in (*PROGRAMS,*UNITS,'snort.lua','home-net.lua','suppress.lua','rule-update.conf','signature-sources.json',
                 'ips-web-isolated.conf','ips-restore.conf','logrotate-snort','frontend-build.json'):
        if not (release/name).is_file(): raise ValueError('Incomplete release: '+name)
    original=json.loads(CONFIG.read_text())
    static_manifest=json.loads((release/'frontend-build.json').read_text())
    for name,expected in static_manifest['files'].items():
        if Path(name).name!=name or digest(release/name)!=expected:
            raise ValueError('Static release checksum differs')
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    BACKUPS.mkdir(parents=True,exist_ok=True,mode=0o700)
    backup=BACKUPS/(time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3))
    backup.mkdir(mode=0o700)
    manifest=dict(moves=[],active={},enabled={},preserved={},data={})
    for unit in LEGACY_UNITS:
        manifest['active'][unit]=run('systemctl','is-active','--quiet',unit,check=False).returncode==0
        manifest['enabled'][unit]=run('systemctl','is-enabled','--quiet',unit,check=False).returncode==0
    protected=[CONFIG,*[Path('/usr/local/bin')/name for name in (*PROGRAMS,'ips-rule-actions')]]
    protected.append(Path('/usr/bin/suricata'))
    manifest['preserved']={str(path):digest(path) for path in protected if path.is_file()}
    shutil.copy2(CONFIG,backup/'legacy-console.conf');os.chmod(backup/'legacy-console.conf',0o600)
    private_json(backup/'migration.json',manifest)
    shutil.copy2(Path(__file__),backup/'deploy-snort3.py')
    (backup/'rollback.sh').write_text('#!/bin/sh\nset -eu\nexec python3 -B '+str(backup/'deploy-snort3.py')+' --rollback '+str(backup)+'\n')
    (backup/'rollback.sh').chmod(0o700)
    def save(): private_json(backup/'migration.json',manifest)
    def move(original_path,archived_path):
        original_path,archived_path=Path(original_path),Path(archived_path)
        if not original_path.exists(): return
        if original_path.is_symlink() or archived_path.exists() or archived_path.is_symlink():
            raise ValueError('Unexpected legacy archive path')
        archived_path.parent.mkdir(parents=True,exist_ok=True)
        manifest['moves'].append([str(original_path),str(archived_path)]);save()
        original_path.rename(archived_path)
    switched=False
    try:
        pause_legacy_manager()
        switched=True
        for unit in LEGACY_UNITS: run('systemctl','stop',unit)
        for unit,enabled in manifest['enabled'].items():
            if enabled: run('systemctl','disable',unit)
        manifest['data']=old_data_metadata();save()
        for name,archived in RENAMED_UNITS.items():
            base=Path('/etc/systemd/system')
            move(base/name,base/archived)
            move(base/(name+'.d'),base/(archived+'.d'))
        move('/etc/systemd/system/nftables.service.d/ips-restore.conf',
             '/etc/systemd/system/nftables.service.d/ips-legacy-restore.conf.disabled')
        move('/etc/logrotate.d/suricata','/etc/ips-legacy/suricata.logrotate')
        with tempfile.TemporaryDirectory(prefix='engine-',dir=STATE) as temporary:
            staged=Path(temporary);sums=unpack_engine(engine_archive,staged)
            run('apt-get','update','-qq')
            run('apt-get','install','-y','--no-install-recommends',*DEPENDENCIES)
            for name in sums:
                source,target=staged/name,Path('/')/name
                if target.is_file() and digest(target)==sums[name]: continue
                if target.exists(): raise ValueError('Existing runtime file differs: '+str(target))
                install_file(source,target,source.stat().st_mode & 0o777)
            with tarfile.open(engine_archive) as package:
                for item in engine_members(package):
                    if not item.issym(): continue
                    target=Path('/')/item.name
                    if target.is_symlink() and str(target.readlink())==item.linkname: continue
                    if target.exists() or target.is_symlink(): raise ValueError('Existing runtime link differs')
                    target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(item.linkname)
            run(str(PREFIX/'bin/snort'),'-V')
            PROGRAM_DIR.mkdir(parents=True,exist_ok=True)
            for name in PROGRAMS: install_file(release/name,PROGRAM_DIR/name,0o644 if name.endswith(('.py','.zip')) else 0o755)
            for receipt in ('backend-build.json','maintenance-build.json','supervisor-build.json'):
                if (release/receipt).is_file():
                    value=json.loads((release/receipt).read_text())
                    for name,expected in value['files'].items():
                        if Path(name).name!=name or digest(release/name)!=expected:raise ValueError('Native program checksum differs')
                        install_file(release/name,PROGRAM_DIR/name,0o755)
                    install_file(release/receipt,PROGRAM_DIR/receipt,0o644)
            for directory in ('/etc/snort','/var/lib/snort/rules','/var/log/snort','/var/log/ips',
                              '/var/lib/snort/update/sources','/var/lib/snort/appid/custom/lua'):
                Path(directory).mkdir(parents=True,exist_ok=True)
            for name in ('snort.lua','home-net.lua','suppress.lua','rule-update.conf',
                         'threshold.config','drop.conf','disable.conf','modify.conf','action-override.conf'):
                target=Path('/etc/snort')/name
                if target.exists():
                    if digest(target)!=digest(release/name): raise ValueError('Native configuration differs: '+name)
                else: install_file(release/name,target,0o600)
            for name in ('local.rules','ips-web-hunting.rules','ips-web-bans.rules','ips-web-bans.lua','snort.rules'):
                target=Path('/var/lib/snort/rules')/name
                if target.exists():
                    if (release/name).exists() and digest(target)!=digest(release/name):
                        raise ValueError('Native local rules differ: '+name)
                elif (release/name).exists(): install_file(release/name,target)
                else: target.write_text('')
            for link,target in ((Path('/var/lib/snort/appid/odp'),PREFIX/'share/appid/odp'),
                                (Path('/var/lib/snort/appid/custom/lua/ips-web-bans.lua'),Path('/var/lib/snort/rules/ips-web-bans.lua'))):
                if link.is_symlink() and link.readlink()==target: continue
                if link.exists() or link.is_symlink(): raise ValueError('Native AppID link differs')
                link.symlink_to(target,target_is_directory=target.is_dir())
            entry=PROGRAM_DIR/'ips-snort-rules'
            sources=Path('/etc/snort/signature-sources.json')
            if not sources.exists() and not sources.is_symlink():
                install_file(release/sources.name,sources,0o644)
            prefix=[str(entry)]
            run(*prefix,'enable-source','snort/community')
            run(*prefix,'--no-reload')
            run(str(PREFIX/'bin/snort'),'-T','-c','/etc/snort/snort.lua')
            if STATIC_DIR.exists() and not (STATIC_DIR/'frontend-build.json').exists():
                raise ValueError('Unrecognized native static directory')
            previous_static=Path(original.get('static_dir','/usr/local/share/ips-web'))
            if not STATIC_DIR.exists():
                if previous_static.is_dir(): shutil.copytree(previous_static,STATIC_DIR)
                else: STATIC_DIR.mkdir(parents=True)
            for name in (*static_manifest['files'],'frontend-build.json','frontend-licenses.txt'):
                install_file(release/name,STATIC_DIR/name)
            if not (STATIC_DIR/'favicon.svg').exists(): install_file(release/'favicon.svg',STATIC_DIR/'favicon.svg')
            private_json(NEW_CONFIG,console_configuration(original))
            for name in UNITS:
                candidate=staged/name;candidate.write_text(render_unit(name,(release/name).read_text()))
                install_file(candidate,Path('/etc/systemd/system')/name)
            isolation=staged/'50-isolation.conf'
            isolation.write_text(render_unit('isolation',(release/'ips-web-isolated.conf').read_text()))
            install_file(isolation,'/etc/systemd/system/ips-web.service.d/50-isolation.conf')
            restore=staged/'ips-restore.conf';restore.write_text(render_unit('restore',(release/'ips-restore.conf').read_text()))
            install_file(restore,'/etc/systemd/system/nftables.service.d/ips-restore.conf')
            install_file(release/'logrotate-snort','/etc/logrotate.d/ips-snort')
            run('groupadd','--system','ips-console',check=False)
            run('systemctl','daemon-reload')
            run('systemctl','enable',*ACTIVE_UNITS,'snort-home-net.timer','ips-log-maintenance.timer')
            run('systemctl','start','ips','ips-event-bridge','ips-rule-manager','ips-web')
            deadline=time.monotonic()+180
            address=original.get('bind','127.0.0.1')
            if address in ('0.0.0.0','::'): address='127.0.0.1'
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while time.monotonic()<deadline:
                try:
                    for unit in ACTIVE_UNITS: run('systemctl','is-active','--quiet',unit)
                    queues=Path('/proc/net/netfilter/nfnetlink_queue').read_text()
                    if not {'0','1','2','3'} <= {line.split()[0] for line in queues.splitlines()}:
                        raise RuntimeError('NFQ listeners not ready')
                    with opener.open('http://'+address+':9000/healthz',timeout=3) as response:
                        if not json.load(response).get('ok'): raise RuntimeError('Console health failed')
                    break
                except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError): time.sleep(1)
            else: raise RuntimeError('Native activation health check timed out')
            for name,expected in manifest['preserved'].items():
                if digest(name)!=expected: raise RuntimeError('Original program/configuration changed: '+name)
            if old_data_metadata()!=manifest['data']:
                raise RuntimeError('Legacy console state changed after it was stopped')
            private_json(LAYOUT,dict(program_dir=str(PROGRAM_DIR),config=str(NEW_CONFIG),static_dir=str(STATIC_DIR),
                                     backup=str(backup),release=(release/'RELEASE').read_text().strip()))
            run('systemctl','start','snort-home-net.timer','ips-log-maintenance.timer')
            shutil.copy2(Path(__file__),backup/'deploy-snort3.py')
            (backup/'rollback.sh').write_text('#!/bin/sh\nset -eu\nexec python3 -B '+str(backup/'deploy-snort3.py')+' --rollback '+str(backup)+'\n')
            (backup/'rollback.sh').chmod(0o700)
            (backup/'complete').write_text('Native services healthy; legacy programs and state preserved\n')
            print(json.dumps(dict(ok=True,legacy_preserved=True,backup=str(backup),port=9000,
                                  program_dir=str(PROGRAM_DIR),static_dir=str(STATIC_DIR))))
    except BaseException:
        if switched: rollback(backup)
        raise


if __name__=='__main__':
    import fcntl
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release')
    parser.add_argument('--engine-package')
    parser.add_argument('--rollback')
    args=parser.parse_args()
    with open('/run/ips-deploy.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.rollback: rollback(args.rollback)
        elif args.release and args.engine_package: activate(args.release,args.engine_package)
        else: parser.error('--release and --engine-package, or --rollback, are required')
