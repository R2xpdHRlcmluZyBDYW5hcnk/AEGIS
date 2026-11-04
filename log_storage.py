"""Verify that managed log aliases still refer to their persistent directories."""
import json
import os
from pathlib import Path

MARKER = Path('/etc/ips-log-storage.json')
ROOT = Path('/var/lib/ips-snort-logs')
BINDINGS = ((Path('/var/log/snort'), 'snort'), (Path('/var/log/ips'), 'events'))


def configuration():
    if not MARKER.exists():
        return {}
    if MARKER.is_symlink():
        raise RuntimeError('日志存储标记不能是符号链接')
    try:
        config = json.loads(MARKER.read_text())
    except PermissionError:
        # Sandboxed Web uses its root-owned service environment and credential
        # configuration; privileged writers still read the private marker.
        return {}
    if config.get('root') != str(ROOT):
        raise RuntimeError('持久日志目录与已安装布局不一致')
    return config


def log_paths():
    configured = os.environ.get('IPS_LOG_STORAGE_ROOT')
    if configured:
        if configured != str(ROOT):
            raise RuntimeError('服务日志目录与已安装布局不一致')
        return ROOT / 'snort', ROOT / 'events/events.json'
    config = configuration()
    if config.get('direct_paths'):
        return ROOT / 'snort', ROOT / 'events/events.json'
    return BINDINGS[0][0], BINDINGS[1][0] / 'events.json'


def validate_log_storage():
    config = configuration()
    if not config:
        return
    if config.get('direct_paths'):
        for path in (ROOT / 'snort', ROOT / 'events'):
            if path.is_symlink() or not path.is_dir():
                raise RuntimeError('持久日志目录不可用：' + str(path))
        return
    for alias, relative in BINDINGS:
        target = ROOT / relative
        if alias.is_symlink() or target.is_symlink() or not alias.is_dir() or not target.is_dir():
            raise RuntimeError('持久日志目录不可用：' + str(alias))
        actual, expected = alias.stat(), target.stat()
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError('持久日志挂载被遮盖或未生效：' + str(alias))
