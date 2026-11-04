"""Read the installed Snort signature inventory without starting detection."""
import platform
from pathlib import Path
import re
import shutil
import subprocess
import threading
import os
from parallel_cpu import shared_cpu, byte_batches

from snort_engine import BINARY
from rule_identity import group_matches

_CACHE = {}
_LOCK = threading.Lock()
LABELS = {'http_inspect': 'HTTP 协议检查', 'stream_tcp': 'TCP 流检查',
          'stream_udp': 'UDP 流检查', 'stream_ip': 'IP 流检查',
          'ssl': 'TLS 协议检查', 'dns': 'DNS 协议检查'}


def identity(value, gid=None):
    """Plain SIDs remain GID 1; explicit identities use GID:SID."""
    if isinstance(value, tuple) and len(value) == 2:
        parts = value
    elif gid is not None:
        parts = (gid, value)
    else:
        value = str(value).removeprefix('sid:')
        parts = value.split(':') if ':' in value else (1, value)
    if len(parts) != 2 or any(not str(x).isdigit() for x in parts):
        raise ValueError('无效 GID:SID')
    generator, signature = map(int, parts)
    if not 1 <= generator <= 8129 or not 1 <= signature <= 4294967295:
        raise ValueError('无效 GID:SID')
    return generator, signature


def key(value, gid=None):
    generator, signature = identity(value, gid)
    return signature if generator == 1 else (generator, signature)


def selector(value, gid=None):
    generator, signature = identity(value, gid)
    return 'sid:' + (str(signature) if generator == 1 else f'{generator}:{signature}')


def decorate(row):
    row = dict(row)
    row.setdefault('gid', 1)
    row['selector'] = selector(row['sid'], row['gid'])
    row['signature'] = f"{row['gid']}:{row['sid']}"
    return row


def disabled(record, selectors):
    for value in selectors:
        kind,_,code=value.partition(':')
        if value.isdigit():
            kind,code='sid',value
        if kind=='sid':
            if identity(code)==(record['gid'],record['sid']): return True
        elif kind=='group':
            import fnmatch
            if fnmatch.fnmatchcase(record['group'],code) or fnmatch.fnmatchcase(record['group']+'.rules',code): return True
        elif kind=='group-source':
            if group_matches(value,record['group'],'Snort 内置'):return True
        elif kind=='msg':
            prefix=code[:-1] if code.endswith('*') else code
            if record['msg'].startswith(prefix): return True
    return False


def _parse_builtin_serial(text):
    rows = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(\d+):(\d+) \(([^)]+)\) (.+)', line.strip())
        if not match:
            continue
        gid, sid = map(int, match.group(1, 2))
        module, message = match.group(3, 4)
        rows[key(sid, gid)] = decorate(dict(gid=gid, sid=sid, msg=f'({module}) {message}',
            module=module, group=f'snort-builtin-{gid}-{module}', action='alert',
            enabled=True, builtin=True, policy_managed=False, line='', search_text=line.casefold()))
    return rows


def _builtin_batch(lines):
    return _parse_builtin_serial(''.join(lines))


def parse_builtin(text):
    if len(text)<1<<20 or os.environ.get('IPS_CPU_CHILD')=='1':
        return _parse_builtin_serial(text)
    rows={}
    for batch in shared_cpu().ordered(_builtin_batch,byte_batches(text.splitlines(keepends=True),size=len)):
        rows.update(batch)
    return rows


def builtin_catalog(config):
    try:
        text = Path(config).read_text()
        # The project enables the builtin rule inventory explicitly.
        if not re.search(r'^\s*ips\.enable_builtin_rules\s*=\s*true\b', text, re.M):
            return {}
        stat = Path(BINARY).stat()
    except FileNotFoundError:
        return {}
    signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
    with _LOCK:
        if _CACHE.get('signature') != signature:
            command = [BINARY, '--list-builtin']
            if platform.machine() not in ('aarch64', 'arm64') and shutil.which('qemu-aarch64'):
                command.insert(0, shutil.which('qemu-aarch64'))
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=20)
            rows = parse_builtin(result.stdout)
            if not rows:
                raise ValueError('Snort 内置签名目录为空')
            _CACHE.update(signature=signature, rows=rows)
        return _CACHE['rows']
