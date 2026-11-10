#!/usr/bin/env python3
"""Transactional session-ID engine switch, followed by console and static updates."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode=True
# Historical installation location; the manifest records the actual version.
PREFIX=Path('/opt/ips-snort3/3.12.4.0')
PROGRAM=Path('/opt/ips-console/bin')
BACKUPS=Path('/var/backups/ips-snort3')
STATE=Path('/var/lib/ips-deploy')
CONFIG=Path('/etc/snort/snort.lua')
WEB_CONFIG=Path('/etc/ips-snort-web.conf')
STATIC=Path('/usr/local/share/ips-snort-web')
LAYOUT=Path('/etc/ips-snort-deployment.json')
SESSION_RECEIPT=Path('/etc/ips-session-logger.json')
ROTATION=Path('/etc/logrotate.d/ips-snort')


def run(*args):
    result=subprocess.run(args,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError('Deployment command failed: '+args[0]+'\n'+result.stdout[-4000:]+result.stderr[-4000:])
    return result


def install(source,target,mode=None):
    target=Path(target)
    if target.is_symlink(): raise ValueError('Unexpected engine destination link')
    target.parent.mkdir(parents=True,exist_ok=True)
    candidate=target.with_name(target.name+'.session-new')
    try:
        shutil.copy2(source,candidate)
        if mode is not None: candidate.chmod(mode)
        candidate.replace(target)
    finally: candidate.unlink(missing_ok=True)


def load(root,name):
    spec=importlib.util.spec_from_file_location(name,Path(root)/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def ready_engine():
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        try:
            run('systemctl','is-active','--quiet','ips')
            queues={line.split()[0] for line in Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()}
            if {'0','1','2','3'}<=queues: return
        except (OSError,RuntimeError): pass
        time.sleep(1)
    raise RuntimeError('Engine listeners did not become ready')


def resume_manager():
    sys.path.insert(0,str(PROGRAM))
    from deployment_support import Client
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        try:
            response=Client().request('maintenance',enabled=False)
            if response.get('ok'): return
        except (OSError,RuntimeError): pass
        time.sleep(.2)
    raise RuntimeError('Could not resume rule manager')


def extractor_config(current, revision):
    if 'ts uid session_id ' not in current:
        if current.count("local common = 'ts uid ")!=1:
            raise ValueError('Unrecognized extractor common-field configuration')
        current=current.replace("local common = 'ts uid ","local common = 'ts uid session_id ",1)
    if revision in ('ndr-session-2','ndr-session-3') and 'alert_suppressed' not in current:
        notice="service = 'notice', on_events = 'ips_logging', fields = "
        if current.count(notice)!=1:
            raise ValueError('Unrecognized extractor notice configuration')
        field="(get_module_version('extractor', 'inspector') >= 1 and 'alert_suppressed ' or '') .. "
        current=current.replace(notice, notice+field,1)
    return current


def validate_upgrade_sources(manifest, previous, expected):
    if manifest.get('session_patch') not in ('ndr-session-1','ndr-session-2','ndr-session-3'):
        raise ValueError('Engine session patch does not match')
    for key in ('snort','libdaq','vectorscan','target'):
        if manifest.get('sources',{}).get(key)!=expected.get(key):
            raise ValueError('Engine sources differ from the pinned release: '+key)
    if previous.get('sources',{}).get('target')!=expected.get('target'):
        raise ValueError('Engine target ABI differs from the installed runtime')


def matching_config(current):
    """Preserve inspector and rule settings while selecting the bundled matcher."""
    selection="search_engine = search_engine or {}\nsearch_engine.search_method = 'hyperscan'"
    if current.rstrip().endswith(selection):
        return current
    return current.rstrip()+'\n\n'+selection+'\n'


def restore_engine_tree(backup):
    """Restore the complete runtime, including DAQ, default Lua and old extensions."""
    previous=Path(backup)/'engine-before'
    if not previous.exists():return
    if previous.is_symlink() or PREFIX.is_symlink():raise ValueError('Unexpected engine tree link')
    if PREFIX.exists():PREFIX.rename(Path(backup)/'engine-failed')
    previous.rename(PREFIX)


def rollback(backup):
    backup=Path(backup).resolve()
    if backup.parent!=BACKUPS or not backup.name.startswith('session-'):
        raise ValueError('Unexpected engine rollback path')
    state=json.loads((backup/'state.json').read_text())
    for name in state['files']:
        path=Path(name)
        if path not in (CONFIG,WEB_CONFIG,LAYOUT,SESSION_RECEIPT,ROTATION,PREFIX/'bin/snort',PREFIX/'engine-manifest.json') and path.parent!=PROGRAM:
            raise ValueError('Unexpected rollback destination')
    for unit in ('ips-web','ips-event-bridge','ips','ips-rule-manager'):
        subprocess.run(['systemctl','stop',unit],check=False,capture_output=True)
    if state.get('engine_tree'):restore_engine_tree(backup)
    for index,(name,saved) in enumerate(state['files'].items()):
        target=Path(name)
        if saved is None:
            if target.exists(): target.replace(backup/('failed-added-'+str(index)))
        else:
            install(backup/saved,target)
    if (backup/'static-before').is_dir():
        if STATIC.is_symlink(): raise ValueError('Unexpected static directory link')
        STATIC.rename(backup/('static-failed-'+secrets.token_hex(3)))
        (backup/'static-before').rename(STATIC)
    run('systemctl','start','ips','ips-rule-manager','ips-event-bridge','ips-web')
    ready_engine();resume_manager()
    if state['home_timer']: run('systemctl','start','snort-home-net.timer')
    print(json.dumps(dict(engine_rollback=True,backup=str(backup))))


def upgrade(release,engine,plugin=None):
    release=Path(release).resolve()
    if not LAYOUT.is_file(): raise ValueError('Complete initial Snort activation first')
    sys.path.insert(0,str(release))
    from deployment_support import Client
    from deployment_support import configuration_lock
    import deployment_support as session_logger
    active=load(release,'deploy-snort3')
    native=load(release,'deploy-native-backend')
    web=load(release,'deploy-backend')
    static=load(release,'deploy-angular')
    BACKUPS.mkdir(parents=True,exist_ok=True,mode=0o700)
    backup=BACKUPS/('session-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3))
    backup.mkdir(mode=0o700)
    state=dict(files={},home_timer=subprocess.run(['systemctl','is-active','--quiet','snort-home-net.timer']).returncode==0)
    paused=False;switched=False;prepared=None
    try:
        pause=Client().request('maintenance',enabled=True)
        if not pause.get('ok'): raise RuntimeError('A rule task is running; engine was left unchanged')
        paused=True
        run('systemctl','stop','snort-home-net.timer')
        with configuration_lock(CONFIG), tempfile.TemporaryDirectory(prefix='session-engine-',dir=STATE) as temporary:
            stage=Path(temporary)
            sums=active.unpack_engine(engine,stage)
            candidate=stage/str(PREFIX).lstrip('/')
            manifest=json.loads((candidate/'engine-manifest.json').read_text())
            previous=json.loads((PREFIX/'engine-manifest.json').read_text())
            revision=manifest.get('session_patch')
            expected=json.loads((release/'build_tools/snort-sources.json').read_text())
            validate_upgrade_sources(manifest,previous,expected)
            if PREFIX.is_symlink() or PREFIX.parent.stat().st_dev!=backup.stat().st_dev:
                raise ValueError('Engine runtime and rollback directory must share a local filesystem')
            prepared=PREFIX.with_name(PREFIX.name+'.upgrade-'+backup.name)
            if prepared.exists():raise ValueError('Engine preparation directory already exists')
            shutil.copytree(candidate,prepared,symlinks=True)
            updated=matching_config(extractor_config(CONFIG.read_text(),revision))
            extension_changes={}
            plugin_path=None
            validation_args=[]
            if plugin:
                extension=load(release,'deploy-session-logger')
                receipt,library=extension.verified_plugin(release,plugin,candidate/'bin/snort')
                if receipt['session_patch']!=revision:
                    raise ValueError('Session extension patch revision differs')
                plugin_path=session_logger.LIBRARY_ROOT/receipt['sha256']/'ndr_session.so'
                if plugin_path.is_symlink() or (plugin_path.exists() and plugin_path.read_bytes()!=library):
                    raise ValueError('Session extension destination differs')
                validation_args=['--plugin-path',str(Path(plugin).resolve()/'ndr_session.so')]
                updated=extension.extension_config(updated.encode()).decode()
                extension_changes[SESSION_RECEIPT]=json.dumps({key:receipt[key] for key in ('sha256','engine_sha256')}).encode()+b'\n'
                extension_changes[PROGRAM/'ips-supervisor']=(release/'ips-supervisor').read_bytes()
                if (release/'supervisor-build.json').is_file():
                    extension_changes[PROGRAM/'supervisor-build.json']=(release/'supervisor-build.json').read_bytes()
                rotation=ROTATION.read_bytes() if ROTATION.exists() else None
                updated_rotation=extension.extension_rotation(rotation)
                if updated_rotation!=rotation:
                    extension_changes[ROTATION]=updated_rotation
            elif SESSION_RECEIPT.exists():
                if json.loads(SESSION_RECEIPT.read_text()).get('engine_sha256')!=manifest['sha256']:
                    raise ValueError('Supply the matching session extension to upgrade this engine')
                validation_args=session_logger.plugin_arguments()
            conf=stage/'snort.lua';conf.write_text(updated);conf.chmod(0o600)
            validation=stage/'validate.lua'
            validation.write_text(updated.replace(str(PREFIX/'etc/snort'),str(prepared/'etc/snort'))
                .replace(str(PREFIX/'lib/daq'),str(prepared/'lib/daq')))
            validation.chmod(0o600)
            environment=dict(os.environ,LD_LIBRARY_PATH=str(prepared/'lib'))
            result=subprocess.run([str(prepared/'bin/snort'),*validation_args,'-T','-c',str(validation)],env=environment,capture_output=True,text=True)
            if result.returncode: raise RuntimeError('Session engine configuration failed validation\n'+result.stdout[-4000:]+result.stderr[-4000:])
            programs=(*native.PROGRAMS,*(['backend-build.json'] if (release/'backend-build.json').is_file() else []))
            if (release/'maintenance-build.json').is_file():
                programs=(*programs,*sorted(native.MAINTENANCE_PROGRAMS-set(programs)),'maintenance-build.json')
            source_config=CONFIG.with_name('signature-sources.json')
            new_config_files=(source_config,) if not source_config.exists() and not source_config.is_symlink() else ()
            for path in (CONFIG,WEB_CONFIG,LAYOUT,*[PROGRAM/name for name in programs],*extension_changes,*new_config_files):
                if path.exists():
                    name='saved-'+str(len(state['files']));shutil.copy2(path,backup/name)
                    state['files'][str(path)]=name
                else: state['files'][str(path)]=None
            if STATIC.is_symlink(): raise ValueError('Unexpected static directory link')
            shutil.copytree(STATIC,backup/'static-before')
            state['engine_tree']=True
            active.private_json(backup/'state.json',state)
            shutil.copy2(Path(__file__),backup/'deploy-session-engine.py')
            (backup/'rollback.sh').write_text('#!/bin/sh\nset -eu\nexec python3 -B '+str(backup/'deploy-session-engine.py')+' --rollback '+str(backup)+'\n')
            (backup/'rollback.sh').chmod(0o700)
            switched=True
            run('systemctl','stop','ips-web','ips-event-bridge','ips')
            PREFIX.rename(backup/'engine-before')
            prepared.rename(PREFIX)
            install(conf,CONFIG,0o600)
            if plugin_path:
                extension.install(library,plugin_path,0o755)
                for path,data in extension_changes.items():
                    extension.install(data,path,0o755 if path.name=='ips-supervisor' else 0o644)
            for name in sums:
                if '/share/licenses/' in name: install(stage/name,Path('/')/name,0o644)
            run('systemctl','start','ips');ready_engine()
            if plugin_path:
                pid=session_logger.process_key()[0]
                if str(plugin_path) not in Path('/proc',str(pid),'maps').read_text():
                    raise RuntimeError('Updated session extension did not load')
                session_logger.mark_loaded()
            # Backend updates may only replace tools and leave service selection empty.
            # Restore the console before their health check, even for identical Go binaries.
            run('systemctl','start','ips-event-bridge','ips-web')
            native.apply(release,web.wait_ready,{},static.snapshot)
            run(sys.executable,'-B',str(release/'deploy-angular.py'),'--release',str(release))
            if hashlib.sha256((PREFIX/'bin/snort').read_bytes()).hexdigest()!=manifest['sha256']:
                raise RuntimeError('Installed engine digest changed')
            layout=json.loads(LAYOUT.read_text());layout.update(session_backup=str(backup),engine_patch=revision,
                engine_version=manifest['sources']['snort']['version'],release=(release/'RELEASE').read_text().strip())
            active.private_json(LAYOUT,layout)
            (backup/'complete').write_text('Session engine and console healthy\n')
        resume_manager()
        if state['home_timer']: run('systemctl','start','snort-home-net.timer')
        print(json.dumps(dict(ok=True,engine_patch=revision,engine_version=manifest['sources']['snort']['version'],backup=str(backup),port=9000)))
    except BaseException:
        if switched: rollback(backup)
        elif paused:
            resume_manager()
            if state['home_timer']: run('systemctl','start','snort-home-net.timer')
        raise
    finally:
        if prepared is not None and prepared.exists():
            if prepared.parent!=PREFIX.parent or not prepared.name.startswith(PREFIX.name+'.upgrade-session-'):
                raise ValueError('Unexpected engine preparation cleanup path')
            shutil.rmtree(prepared)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release');parser.add_argument('--engine-package');parser.add_argument('--session-logger-directory');parser.add_argument('--rollback')
    args=parser.parse_args()
    if os.geteuid()!=0: parser.error('Run as root')
    with open('/run/ips-deploy.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.rollback: rollback(args.rollback)
        elif args.release and args.engine_package: upgrade(args.release,args.engine_package,args.session_logger_directory)
        else: parser.error('Specify release and engine package, or rollback')
