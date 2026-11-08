"""Explicit Snort wrapper update with validation, hot reload and rollback."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from deployment_support import Client
from deployment_support import BINARY, SOCKET, SnortControl, configuration_lock
import deployment_support as session_logger

CONFIG = Path('/etc/snort/snort.lua')
BACKUPS = Path('/var/backups/ips-snort-config')


def install(data, path, mode):
    staged = path.with_name(path.name+'.ndr-new')
    try:
        with staged.open('wb') as handle:
            os.chmod(staged, mode)
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        staged.replace(path)
        if os.name == 'posix':
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
    finally:
        staged.unlink(missing_ok=True)


def reload_config(control):
    if session_logger.plugin_arguments():
        session_logger.reload_extension(control, CONFIG)
        return
    generation = control.command('show_config_generation()', timeout=5)
    reply = control.command('snort.reload_config('+json.dumps(str(CONFIG))+')', timeout=300)
    if any(word in reply.lower() for word in ('failed', 'restart required', 'bad config', 'error:')):
        raise RuntimeError('Snort configuration reload failed')
    deadline = time.monotonic()+60
    while control.command('show_config_generation()', timeout=5) == generation:
        if time.monotonic() >= deadline: raise RuntimeError('Snort configuration reload timed out')
        time.sleep(.1)


def deploy(release):
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise PermissionError('Snort configuration deployment requires root')
    candidate = (Path(release)/'snort.lua').read_bytes()
    client = Client()
    if not client.request('maintenance', enabled=True).get('ok'):
        raise RuntimeError('Rule manager is busy; no configuration changed')
    try:
        with configuration_lock(CONFIG):
            original = CONFIG.read_bytes(); mode = CONFIG.stat().st_mode & 0o777
            engine = session_logger.process_key()
            backup = BACKUPS/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            backup.mkdir(parents=True, mode=0o700)
            install(original, backup/'snort.lua.before', 0o600)
            pending = backup/'snort.lua.candidate'
            install(candidate, pending, 0o600)
            checked = subprocess.run([BINARY, *session_logger.plugin_arguments(), '-T', '-c', str(pending)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            install(checked.stdout, backup/'validation.log', 0o600)
            if checked.returncode:
                raise RuntimeError('Snort validation failed; original configuration retained; see '+str(backup))
            if CONFIG.read_bytes() != original or session_logger.process_key() != engine:
                raise RuntimeError('Configuration or engine changed during validation; update cancelled')
            control = SnortControl(SOCKET)
            try:
                install(candidate, CONFIG, mode)
                reload_config(control)
                if session_logger.process_key() != engine or CONFIG.read_bytes() != candidate:
                    raise RuntimeError('Snort configuration or process verification failed')
            except BaseException:
                install(original, CONFIG, mode)
                try:
                    reload_config(control)
                    if session_logger.process_key() != engine:
                        raise RuntimeError('Engine identity changed')
                except BaseException as rollback_error:
                    raise RuntimeError('Original file restored but runtime rollback failed; backup: '+str(backup)) from rollback_error
                raise
            result = dict(snort_config_updated=True, hot_reload=True, engine_preserved=True,
                          sha256=hashlib.sha256(candidate).hexdigest(), backup=str(backup))
            install((json.dumps(result)+'\n').encode(), backup/'verification.json', 0o600)
            print(json.dumps(result))
    finally:
        client.request('maintenance', enabled=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    args = parser.parse_args()
    import fcntl
    with open('/run/ips-deploy.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        subprocess.run(['sha256sum', '--strict', '-c', 'SHA256SUMS'], cwd=args.release,
                       stdout=subprocess.DEVNULL, check=True)
        deploy(args.release)
