"""Read the administrator-installed native extension receipt; never evaluate it."""
import hashlib
import json
from pathlib import Path
import re
import time

RECEIPT = Path('/etc/ips-session-logger.json')
LIBRARY_ROOT = Path('/opt/ips-snort3/3.12.4.0/lib/ndr')
# This runtime directory is shared by both deployment layouts and already
# writable inside the manager's systemd sandbox (its control/status socket).
MARKER = Path('/run/ips-rule-manager/session-logger-loaded.json')


def plugin_arguments(receipt=RECEIPT):
    if not receipt.exists(): return []
    value = json.loads(receipt.read_text())
    digest = value.get('sha256', '')
    if not re.fullmatch(r'[a-f0-9]{64}', digest): raise ValueError('Invalid session extension receipt')
    library = LIBRARY_ROOT / digest / 'ndr_session.so'
    if library.is_symlink() or not library.is_file() or hashlib.sha256(library.read_bytes()).hexdigest() != digest:
        raise ValueError('Session extension checksum differs')
    return ['--plugin-path', str(library)]


def process_key():
    pid = int(Path('/run/snort/snort.pid').read_text())
    # PID reuse must not suppress activation for a new engine instance.
    start = Path('/proc') / str(pid) / 'stat'
    return [pid, start.read_text().rsplit(')', 1)[1].split()[19],
            Path('/proc/sys/kernel/random/boot_id').read_text().strip()]


def mark_loaded():
    value = dict(process=process_key(), sha256=json.loads(RECEIPT.read_text())['sha256'])
    candidate = MARKER.with_suffix('.new')
    candidate.write_text(json.dumps(value) + '\n'); candidate.replace(MARKER)


def reload_extension(control, config):
    arguments = plugin_arguments()
    if not arguments: return
    before = control.command('show_config_generation()', timeout=5)
    reply = control.command('snort.reload_config(' + json.dumps(str(config)) + ',' + json.dumps(arguments[1]) + ')', timeout=300)
    if any(word in reply.lower() for word in ('failed', 'restart required', 'bad config', 'error:')):
        raise RuntimeError('Session extension configuration reload failed')
    deadline = time.monotonic() + 60
    while control.command('show_config_generation()', timeout=5) == before:
        if time.monotonic() >= deadline: raise RuntimeError('Session extension reload did not complete')
        time.sleep(.1)
    mark_loaded()


def ensure_loaded(manager):
    """Recover activation if an older, already-running supervisor respawns Snort.

    Cold starts safely omit an unavailable optional module. Updated supervisors
    load it at startup; this one-time-per-engine guard covers the transition.
    Lock order matches rule jobs: configuration, then engine control.
    """
    if not RECEIPT.exists(): return
    value = json.loads(RECEIPT.read_text())
    if not re.fullmatch(r'[a-f0-9]{64}', value.get('engine_sha256', '')):
        raise ValueError('Invalid session extension engine receipt')
    from snort_engine import BINARY, configuration_lock, SnortControl
    key = dict(process=process_key(), sha256=value['sha256'])
    if MARKER.exists() and json.loads(MARKER.read_text()) == key: return
    with manager.lock:
        if manager.busy or manager.paused: return
        with configuration_lock(manager.module.SNORT_CONF):
            with manager.runtime.engine_gate:
                if hashlib.sha256(Path(BINARY).read_bytes()).hexdigest() != value['engine_sha256']:
                    raise RuntimeError('Session extension engine ABI differs')
                reload_extension(SnortControl(manager.module.ENGINE_SOCKET), manager.module.SNORT_CONF)
