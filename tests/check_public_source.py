"""Check the Git index for credentials, personal paths and runtime artifacts.

Only paths and finding categories are printed, never matched secret values.
Run after staging the intended public source with git add.
"""
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    '.db', '.sqlite', '.sqlite3', '.log', '.pcap', '.pcapng', '.exe', '.dll',
    '.so', '.a', '.o', '.zip', '.tgz', '.gz', '.pem', '.key', '.p12', '.pfx',
    '.woff', '.woff2', '.pyc',
}
FORBIDDEN_PARTS = {'node_modules', '__pycache__', '.angular', 'dist', 'backup', 'artifacts'}
PATTERNS = {
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'access token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b'),
    'personal path': re.compile(r'(?i)(?:[A-Z]:[\\/]Users[\\/][A-Z0-9_. -]+[\\/]|/mnt/[a-z]/Users/[A-Z0-9_. -]+/|/home/[A-Z0-9_.-]+/)'),
}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                         ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')


def findings(name, data):
    path = Path(name)
    if path.suffix.lower() in FORBIDDEN_SUFFIXES or set(path.parts) & FORBIDDEN_PARTS:
        yield 'generated, binary, credential or runtime file'
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError:
        yield 'non-text content'
        return
    if '\0' in text:
        yield 'binary content'
    for category, pattern in PATTERNS.items():
        if pattern.search(text):
            yield category
    if name == 'ips-web.conf':
        config = json.loads(text)
        if any(config.get(field) for field in ('password_sha256', 'password_pbkdf2')):
            yield 'production authentication material in template'
    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if any(address in network for network in PRIVATE_NETWORKS):
            # Standard RFC 1918 ranges are public constants, not deployment hosts.
            standard_range = any(
                text[match.start():].startswith(str(network)) for network in PRIVATE_NETWORKS)
            if not standard_range:
                yield 'private IPv4 host or deployment address'
                break


def main():
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    problems = []
    for name in filter(None, names):
        # Scan the exact staged blob, not a potentially different working copy.
        data = subprocess.check_output(['git', 'show', ':' + name], cwd=ROOT)
        problems.extend((name, category) for category in findings(name, data))
    for name, category in problems:
        print(name + ': ' + category)
    if problems:
        return 1
    print('Public source index passed credential, address, path and artifact checks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
