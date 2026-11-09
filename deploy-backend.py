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
RESOURCE_LIMITS = {'cache_memory_percent':(.1,10),
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
                if health.get('ok') and health.get('event_db_ready',True):
                    return health
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Console health check failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--postgresql',action='store_true')
    parser.add_argument('--reset-event-data',action='store_true')
    parser.add_argument('--console-only',action='store_true')
    parser.add_argument('--with-rule-manager',action='store_true')
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
    spec = importlib.util.spec_from_file_location('static_deployer', release / 'deploy-angular.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return upgrade(release,helper,overrides,postgresql=args.postgresql,reset_event_data=args.reset_event_data,
                   console_only=args.console_only,with_rule_manager=args.with_rule_manager)


def upgrade(release,helper,overrides,postgresql=False,reset_event_data=False,console_only=False,with_rule_manager=False):
    if with_rule_manager and not console_only:raise ValueError('--with-rule-manager requires --console-only')
    if Path('/etc/systemd/system/ips-web.service.d/50-isolation.conf').is_file():
        spec = importlib.util.spec_from_file_location('web_isolation', release / 'deploy-native-backend.py')
        isolation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolation)
        config=json.loads(CONFIG.read_bytes())
        if reset_event_data and not postgresql:raise ValueError('--reset-event-data requires --postgresql')
        if postgresql and not config.get('database_url') and not reset_event_data:
            raise ValueError('Switching SQLite to PostgreSQL requires explicit --reset-event-data')
        if postgresql or (config.get('database_url') and not console_only):
            # Validate the complete release before installing runtime dependencies.
            isolation.validate_native_release(release)
            database_spec=importlib.util.spec_from_file_location('postgresql_dependency',release/'deploy-postgresql.py')
            dependency=importlib.util.module_from_spec(database_spec);database_spec.loader.exec_module(dependency)
            installed=dependency.install()
            overrides=dict(overrides,database_url=installed['database_url'])
        return isolation.apply(release, wait_ready, overrides, helper.snapshot,reset_event_data=reset_event_data,
                               console_only=console_only,with_rule_manager=with_rule_manager)
    raise RuntimeError('Native Go backend requires the independent isolated service layout')


if __name__ == '__main__':
    main()
