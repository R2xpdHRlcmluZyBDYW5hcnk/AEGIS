#!/usr/bin/env python3
"""Opt-in console backend upgrade with protected-state checks and rollback."""
import argparse
import datetime
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from deployment_layout import layout

sys.dont_write_bytecode = True
TARGET = Path(layout()['program_dir'])/'ips-web'
CONFIG = Path(layout()['config'])
BACKUP_ROOT = Path('/var/backups/ips-console')
RESOURCE_LIMITS = {'read_workers':(1,8), 'cache_memory_percent':(.1,10),
                   'cache_max_mib':(1,1024), 'preload_memory_mib':(1,1024),
                   'stats_batch_size':(128,8192), 'stats_duty_percent':(5,80),
                   'llm_summary_max_tokens':(384,1024)}


def resource_overrides(values):
    result = {}
    for name,(minimum,maximum) in RESOURCE_LIMITS.items():
        value = values.get(name)
        if value is None:
            continue
        if not math.isfinite(value) or not minimum<=value<=maximum:
            raise ValueError('Invalid resource setting: '+name)
        result[name] = value
    return result


def replace_configuration(data):
    staged = CONFIG.with_name(CONFIG.name+'.aegis-'+str(os.getpid()))
    try:
        with open(staged,'wb') as handle:
            os.chmod(staged,0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged,CONFIG)
    finally:
        staged.unlink(missing_ok=True)


def install(source):
    staged = TARGET.with_name(TARGET.name + '.aegis-' + str(os.getpid()))
    try:
        shutil.copy2(source, staged)
        os.chmod(staged, 0o755)
        os.replace(staged, TARGET)
    finally:
        staged.unlink(missing_ok=True)


def independent_console():
    return subprocess.run(['systemctl', 'is-active', '--quiet', 'ips-web.service'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def restart_console(parent):
    if independent_console():
        subprocess.run(['systemctl', 'restart', 'ips-web.service'], check=True)
        return
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            args = (proc / 'cmdline').read_bytes().split(b'\0')
            if int(status['PPid']) != int(parent) or os.fsencode(TARGET) not in args:
                continue
            os.kill(int(proc.name), signal.SIGTERM)
            for _ in range(100):
                if not proc.exists():
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('Console did not stop; engine was left running')
        except (FileNotFoundError, ProcessLookupError):
            continue


def wait_ready(cfg):
    host = cfg.get('bind', '127.0.0.1')
    host = '127.0.0.1' if host == '0.0.0.0' else '::1' if host == '::' else host
    if ':' in host:
        host = '[' + host.strip('[]') + ']'
    url = 'http://%s:%s/healthz' % (host, cfg.get('port', 9000))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(60):
        try:
            with opener.open(url, timeout=2) as response:
                health = json.load(response)
                if health.get('ok'):
                    return health
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Console health check failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    for name in RESOURCE_LIMITS:
        parser.add_argument('--'+name.replace('_','-'),type=float if name in ('cache_memory_percent','stats_duty_percent') else int)
    args = parser.parse_args()
    try:
        overrides = resource_overrides(vars(args))
    except ValueError as exc:
        parser.error(str(exc))
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    release = args.release.resolve()
    lock = open('/run/ips-deploy.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    subprocess.run(['sha256sum', '--strict', '-c', 'SHA256SUMS'], cwd=release,
                   stdout=subprocess.DEVNULL, check=True)
    compile((release / 'ips-web').read_bytes(), 'ips-web', 'exec')
    spec = importlib.util.spec_from_file_location('static_deployer', release / 'deploy-angular.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return upgrade(release,helper,overrides)


def upgrade(release,helper,overrides):
    if Path('/etc/systemd/system/ips-web.service.d/50-isolation.conf').is_file():
        spec = importlib.util.spec_from_file_location('web_isolation', release / 'deploy-native-backend.py')
        isolation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolation)
        return isolation.apply(release, wait_ready, overrides, helper.snapshot)
    if (release/'libsqlite3-ndr.so').is_file():
        raise RuntimeError('The private SQLite runtime requires the isolated Web service layout')
    original_config = CONFIG.read_bytes()
    cfg = json.loads(original_config)
    updated_cfg = dict(cfg,**overrides)
    configuration_changed = updated_cfg != cfg
    before = helper.snapshot(cfg)
    if before['files'][str(TARGET)] == helper.digest(release / 'ips-web') and not configuration_changed:
        print(json.dumps({'backend_unchanged': True}))
        return
    token = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = BACKUP_ROOT / token
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(TARGET, backup / 'ips-web-before')
    if configuration_changed:
        (backup/'ips-web.conf-before').write_bytes(original_config)
        os.chmod(backup/'ips-web.conf-before',0o600)
    (backup / 'state.before.json').write_text(json.dumps(before, indent=2))
    if configuration_changed and CONFIG.read_bytes()!=original_config:
        raise RuntimeError('Configuration changed during deployment; no update was applied')
    try:
        if configuration_changed:
            replace_configuration((json.dumps(updated_cfg,ensure_ascii=False,indent=2)+'\n').encode())
        install(release / 'ips-web')
        restart_console(before['supervisor_pid'])
        wait_ready(cfg)
        after = helper.snapshot(cfg)
        assert after['files'][str(TARGET)] == helper.digest(release / 'ips-web'), 'Backend hash mismatch'
        for path, digest in before['files'].items():
            if path != str(TARGET) and not (configuration_changed and path==str(CONFIG)):
                assert after['files'].get(path) == digest, 'Protected file changed: ' + path
        assert json.loads(CONFIG.read_bytes())==updated_cfg, 'Unexpected configuration change'
        for key in ('db_inode', 'engine_pid', 'supervisor_pid', 'crontab'):
            assert after[key] == before[key], 'Protected state changed: ' + key
        assert after['db_rows'] >= before['db_rows'], 'Historical events disappeared'
    except BaseException:
        install(backup / 'ips-web-before')
        if configuration_changed:
            replace_configuration(original_config)
        restart_console(before['supervisor_pid'])
        wait_ready(cfg)
        raise
    (backup / 'state.after.json').write_text(json.dumps(after, indent=2))
    print(json.dumps({'backend_updated': True, 'backup': str(backup), 'engine_pid': after['engine_pid'],
                      'database_preserved': True, 'configuration_unchanged': not configuration_changed,
                      'resource_settings': overrides, 'rules_unchanged': True}))


if __name__ == '__main__':
    main()
