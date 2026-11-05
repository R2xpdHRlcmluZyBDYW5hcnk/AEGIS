#!/usr/bin/env python3
"""Validate, back up and activate the detector supervisor without replacing Snort."""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

PROGRAMS = ('ips-supervisor', 'snort_engine.py')
FILES = (*PROGRAMS, 'deploy-supervisor.py', 'deploy-nft.py', 'log_storage.py')
BACKUPS = Path('/var/backups/ips-supervisor')
ENGINE_PID = Path('/run/snort/snort.pid')
NATIVE_PROGRAM = Path('/opt/ips-console/bin')
LEGACY_PROGRAM = Path('/usr/local/bin')
PROC = Path('/proc')
COMPANIONS = ('ips-web.service', 'ips-event-bridge.service', 'ips-rule-manager.service')


def load(path):
    loader = importlib.machinery.SourceFileLoader(path.stem, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=120).stdout


def process(unit):
    return int(run('systemctl', 'show', unit, '-p', 'MainPID', '--value').strip())


@contextmanager
def rule_maintenance():
    from ips_control import Client
    state = run('systemctl', 'show', 'ips-rule-manager.service', '-p', 'StateDirectory', '--value').strip()
    if state not in ('ips-rule-manager', 'ips-snort-rule-manager') or (Path('/var/lib') / state / 'maintenance').exists():
        raise RuntimeError('Rule manager is already in maintenance or its layout is unknown')
    client = Client(timeout=10)
    response = client.request('maintenance', enabled=True)
    if not response.get('ok'):
        raise RuntimeError(response.get('error', 'A rule operation is running'))
    try:
        yield
    finally:
        response = client.request('maintenance', enabled=False)
        if not response.get('ok'):
            raise RuntimeError(response.get('error', 'Could not resume rule operations'))


def wait_ready(candidate, previous_pid):
    from snort_engine import SnortControl
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            pid = int(ENGINE_PID.read_text())
            if pid != previous_pid and candidate.queue_listeners() == candidate.QUEUE_IDS:
                SnortControl().command('show_config_generation()', timeout=2)
                run('systemctl', 'is-active', '--quiet', 'ips.service')
                return pid
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
        time.sleep(0.5)
    raise RuntimeError('Snort did not reopen all four NFQUEUE listeners')


def prepare(output):
    root = Path(__file__).resolve().parent
    output = output.resolve()
    if output.is_relative_to(root):
        raise ValueError('Stage supervisor releases outside the source directory')
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    for name in FILES:
        data = (root / name).read_bytes().removeprefix(b'\xef\xbb\xbf').replace(b'\r\n', b'\n')
        compile(data, name, 'exec')
        (output / name).write_bytes(data)
        checksums.append(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
    (output / 'SHA256SUMS').write_text(''.join(checksums), encoding='utf-8', newline='\n')


def upgrade(release):
    program = NATIVE_PROGRAM if (NATIVE_PROGRAM / 'ips-supervisor').is_file() else LEGACY_PROGRAM
    from snort_engine import configuration_lock
    nft = load(release / 'deploy-nft.py')
    candidate = load(release / 'ips-supervisor')
    targets = [program / name for name in PROGRAMS]
    if any(path.is_symlink() or not path.is_file() for path in targets):
        raise ValueError('Unexpected installed supervisor path')
    supervisor_pid = process('ips.service')
    args = (PROC / str(supervisor_pid) / 'cmdline').read_bytes().split(b'\0')
    if os.fsencode(targets[0]) not in args or load(targets[0]).nft_rules() != candidate.nft_rules():
        raise ValueError('Supervisor deployment must preserve the running queue policy')
    original = {path: (path.read_bytes(), path.stat().st_mode & 0o777) for path in targets}
    replacement = {path: (release / path.name).read_bytes() for path in targets}
    for path, data in replacement.items():
        compile(data, str(path), 'exec')
    with rule_maintenance(), configuration_lock():
        companions = {unit: process(unit) for unit in COMPANIONS}
        pid = int(ENGINE_PID.read_text())
        policy = nft.policy_signature(json.loads(run(nft.NFT, '-j', 'list', 'table', 'inet', 'ips')))
        token = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = BACKUPS / token
        backup.mkdir(parents=True, mode=0o700)
        for path, (data, mode) in original.items():
            nft.atomic_write(data, backup / path.name, mode)

        restarted = False
        try:
            for path in targets:
                nft.atomic_write(replacement[path], path, original[path][1])
            restarted = True
            run('systemctl', 'restart', 'ips.service')
            active_pid = wait_ready(candidate, pid)
            if (any(path.read_bytes() != replacement[path] for path in targets) or
                    companions != {unit: process(unit) for unit in COMPANIONS} or
                    policy != nft.policy_signature(json.loads(run(nft.NFT, '-j', 'list', 'table', 'inet', 'ips')))):
                raise RuntimeError('Supervisor deployment did not preserve companion services or queue policy')
        except BaseException:
            for path, (data, mode) in original.items():
                nft.atomic_write(data, path, mode)
            if restarted:
                run('systemctl', 'stop', 'ips.service')
                candidate.archive_native_logs(threading.Event())
                run('systemctl', 'start', 'ips.service')
                wait_ready(candidate, pid)
            raise
        print(json.dumps(dict(supervisor_updated=True, backup=str(backup), snort_pid=active_pid, queues=[0, 1, 2, 3])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', type=Path)
    mode.add_argument('--release', type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare)
    else:
        import fcntl
        sys.dont_write_bytecode = True
        program = NATIVE_PROGRAM if (NATIVE_PROGRAM / 'ips-supervisor').is_file() else LEGACY_PROGRAM
        sys.path.insert(0, str(program))
        with open('/run/ips-deploy.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            upgrade(args.release.resolve())
