"""Validate and hot-load the optional native session logger with rollback."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from deployment_support import Client
from deployment_support import log_paths
from deployment_support import BINARY, configuration_lock, SnortControl
import deployment_support as session_logger

CONFIG = Path('/etc/snort/snort.lua')
PROGRAM = Path('/opt/ips-console/bin')
BACKUPS = Path('/var/backups/ips-session-logger')
ROTATION = Path('/etc/logrotate.d/ips-snort')


def install(data, path, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(path.name+'.ndr-new')
    with staged.open('wb') as handle:
        handle.write(data); handle.flush(); os.fsync(handle.fileno())
    staged.chmod(mode); staged.replace(path)


def verified_plugin(release, plugin, engine):
    plugin = Path(plugin)
    manifest = json.loads((plugin/'session-logger.json').read_text())
    library = (plugin/'ndr_session.so').read_bytes()
    if (manifest.get('session_patch') not in ('ndr-session-1', 'ndr-session-2', 'ndr-session-3') or manifest.get('version') != 1
            or hashlib.sha256(Path(engine).read_bytes()).hexdigest() != manifest['engine_sha256']
            or hashlib.sha256(library).hexdigest() != manifest['sha256']
            or hashlib.sha256((release/'native_session_logger.cc').read_bytes()).hexdigest() != manifest['source_sha256']):
        raise ValueError('Native extension source, binary or engine ABI differs')
    return manifest, library


def extension_config(config):
    marker = b"if get_module_version('ndr_session', 'inspector') >= 1 then"
    if marker in config:
        return config
    return config + b"\n"+marker+b"\n    ndr_session = { snapshot_interval = 30, state_limit = 32 }\nend\n"


def extension_rotation(rotation):
    if rotation and b'*ndr_session.json' not in rotation:
        return rotation.replace(b'*alert_json.txt', b'*alert_json.txt '+str(log_paths()[0]/'*ndr_session.json').encode(), 1)
    return rotation


def deploy(release, plugin):
    release = Path(release)
    manifest, library = verified_plugin(release, plugin, BINARY)
    for name in ('deployment_support.py',):
        if (PROGRAM/name).read_bytes() != (release/name).read_bytes():
            raise ValueError('Deploy the matching console backend first')
    candidate = session_logger.LIBRARY_ROOT / manifest['sha256'] / 'ndr_session.so'
    if candidate.exists() and candidate.read_bytes() != library: raise ValueError('Extension destination differs')
    client = Client(); paused = client.request('maintenance', enabled=True)
    if not paused.get('ok'): raise RuntimeError('Rule manager is busy')
    try:
        with configuration_lock(CONFIG):
            control = SnortControl('/run/snort/control.sock')
            pid = session_logger.process_key()
            config = extension_config(CONFIG.read_bytes())
            paths = [CONFIG, session_logger.RECEIPT, ROTATION]
            before = {path:path.read_bytes() if path.exists() else None for path in paths}
            token = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            backup = BACKUPS/token; backup.mkdir(parents=True, mode=0o700)
            for index, (path, data) in enumerate(before.items()):
                if data is not None: (backup/str(index)).write_bytes(data)
            (backup/'manifest.json').write_text(json.dumps({str(path):str(i) if data is not None else None
                for i,(path,data) in enumerate(before.items())}, indent=2)+'\n')
            install(library, candidate, 0o755)
            receipt = dict(sha256=manifest['sha256'], engine_sha256=manifest['engine_sha256'])
            candidate_config = backup/'candidate.lua'; candidate_config.write_bytes(config)
            result = subprocess.run([BINARY, '--plugin-path', str(candidate), '-T', '-c', str(candidate_config)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            if result.returncode: raise RuntimeError('Native session configuration validation failed; no runtime change')
            reloaded = False
            try:
                install(config, CONFIG)
                install(json.dumps(receipt).encode()+b'\n', session_logger.RECEIPT)
                rotation = extension_rotation(before[ROTATION])
                if rotation != before[ROTATION]:
                    install(rotation, ROTATION)
                reloaded = True
                session_logger.reload_extension(control, CONFIG)
                if session_logger.process_key() != pid: raise RuntimeError('Detection process changed')
            except BaseException:
                for path,data in before.items():
                    if data is None: path.unlink(missing_ok=True)
                    else: install(data, path, 0o755 if path.name == 'ips-supervisor' else 0o644)
                session_logger.MARKER.unlink(missing_ok=True)
                if reloaded:
                    # No new configuration table remains when the extension was
                    # not installed before this transaction. Loaded code may stay
                    # mapped, but the old configuration remains authoritative.
                    previous = session_logger.plugin_arguments()
                    if previous: session_logger.reload_extension(control, CONFIG)
                    else:
                        before_generation=control.command('show_config_generation()',timeout=5)
                        reply=control.command('snort.reload_config('+json.dumps(str(CONFIG))+')',timeout=300)
                        if any(word in reply.lower() for word in ('failed','error:','bad config','restart required')):
                            raise RuntimeError('Extension rollback reload failed; backup retained')
                        import time
                        deadline=time.monotonic()+60
                        while control.command('show_config_generation()',timeout=5)==before_generation:
                            if time.monotonic()>deadline:raise RuntimeError('Extension rollback did not complete; backup retained')
                            time.sleep(.1)
                raise
            print(json.dumps(dict(session_logger_enabled=True, hot_reload=True, engine_preserved=True, backup=str(backup))))
    finally:
        client.request('maintenance', enabled=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True); parser.add_argument('--plugin', required=True)
    args = parser.parse_args(); deploy(args.release, args.plugin)
