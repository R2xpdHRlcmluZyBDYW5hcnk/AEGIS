"""Check the Git index for credentials, personal paths and runtime artifacts.

Only paths and finding categories are printed, never matched secret values.
Run after staging the intended public source with git add.
"""
import ipaddress
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import zlib

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


def documentation_png(data):
    """Allow documentation pixels without text, EXIF or other private metadata."""
    if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) > 8 << 20:
        return False
    offset, chunks = 8, []
    while offset + 12 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], 'big')
        end = offset + 12 + size
        if end > len(data):
            return False
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:end - 4]
        if kind not in (b'IHDR', b'IDAT', b'IEND', b'sRGB'):
            return False
        if zlib.crc32(kind + body) != int.from_bytes(data[end - 4:end], 'big'):
            return False
        if kind == b'IHDR':
            if chunks or size != 13:
                return False
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', body)
            if not (0 < width <= 4096 and 0 < height <= 4096 and depth == 8 and color in (2, 6)
                    and compression == filtering == interlace == 0):
                return False
        elif not chunks:
            return False
        elif kind == b'IEND':
            return size == 0 and end == len(data) and b'IDAT' in chunks
        elif kind == b'sRGB' and (size != 1 or body[0] > 3 or b'IDAT' in chunks or kind in chunks):
            return False
        elif kind == b'IDAT' and size == 0:
            return False
        chunks.append(kind)
        offset = end
    return False


def findings(name, data):
    path = Path(name)
    if path.parent.as_posix() == 'docs/images' and path.suffix.lower() == '.png':
        if not documentation_png(data):
            yield 'invalid documentation PNG or embedded metadata'
        return
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
