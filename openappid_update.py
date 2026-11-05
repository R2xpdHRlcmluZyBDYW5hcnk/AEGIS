"""Bounded official OpenAppID downloads and an atomic detector-directory switch.

The rule manager owns the enclosing rollback journal and engine reload. Detector
Lua is trusted vendor code, never supplied through searches, events or the LLM.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
import urllib.request

ROOT = Path('/var/lib/snort/appid')
PAGE = 'https://www.snort.org/downloads'
CHECKSUM = 'https://www.snort.org/downloads/openappid/md5s'
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024


def atomic_json(path, value):
    candidate = path.with_name(path.name + '.new')
    with candidate.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True); handle.write('\n')
        handle.flush(); os.fsync(handle.fileno())
    candidate.replace(path)


def _allowed(url):
    parsed = urlsplit(url)
    host = (parsed.hostname or '').lower()
    return (parsed.scheme == 'https' and not parsed.username and not parsed.password
            and parsed.port in (None, 443) and (host in ('snort.org', 'www.snort.org')
            or host.endswith('.amazonaws.com') or host.endswith('.cloudfront.net')))


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if not _allowed(newurl): raise ValueError('OpenAppID 下载重定向地址不受信任')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def fetch(url, target=None, maximum=2 * 1024 * 1024):
    if not _allowed(url): raise ValueError('OpenAppID 下载地址不受信任')
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'Snort-NDR-OpenAppID/1', 'Cache-Control': 'no-cache'})
        with urllib.request.build_opener(Redirects()).open(request, timeout=45) as response:
            if not _allowed(response.url): raise ValueError('Unexpected redirect')
            size = 0; chunks = []; deadline = time.monotonic() + 180
            while True:
                block = response.read(min(65536, maximum + 1 - size))
                if time.monotonic() > deadline: raise TimeoutError('OpenAppID download deadline')
                if not block: break
                size += len(block)
                if size > maximum: raise ValueError('OpenAppID 下载超过大小上限')
                if target: target.write(block)
                else: chunks.append(block)
            return b''.join(chunks)
    except Exception:
        # HTTP exceptions can embed presigned redirect URLs. Never expose them.
        raise RuntimeError('OpenAppID 官方下载失败或响应超过限制') from None


def snapshot(root=ROOT):
    root = Path(root); link = root / 'odp'; receipt = root / 'update.json'
    if not link.exists() and not link.is_symlink(): return None
    if not link.is_symlink(): raise ValueError('OpenAppID odp 必须是受管理的符号链接')
    target = os.readlink(link)
    validate_target(root, target)
    return dict(target=target, receipt=json.loads(receipt.read_text()) if receipt.exists() else None)


def validate_target(root, target):
    path = Path(target)
    if not path.is_absolute(): path = root / path
    resolved = path.resolve()
    bundled = Path('/opt/ips-snort3/3.12.4.0/share/appid/odp')
    releases = (root / 'releases').resolve()
    if resolved != bundled and not (resolved.parent == releases and re.fullmatch(r'[a-f0-9]{64}', resolved.name)):
        raise ValueError('Unexpected OpenAppID detector target')
    if not resolved.is_dir(): raise ValueError('OpenAppID detector target is missing')


def switch(root, target):
    validate_target(root, target)
    staged = root / 'odp.new'
    if staged.exists() or staged.is_symlink(): staged.unlink()
    staged.symlink_to(target, target_is_directory=True)
    staged.replace(root / 'odp')


def restore(value, root=ROOT):
    if value is None: return
    root = Path(root); switch(root, value['target'])
    if value['receipt'] is None: (root / 'update.json').unlink(missing_ok=True)
    else: atomic_json(root / 'update.json', value['receipt'])


def extract(archive, destination):
    """Never invoke tar or extractall on a remotely supplied archive."""
    total = 0; seen = set(); count = 0
    with tarfile.open(archive, 'r:gz') as package:
        for member in package:
            count += 1
            path = PurePosixPath(member.name)
            if (count > 20000 or '\\' in member.name or path.is_absolute() or '..' in path.parts
                    or '.git' in path.parts or not path.parts or path.parts[0] != 'odp' or str(path) in seen
                    or not (member.isfile() or member.isdir()) or member.size < 0
                    or member.size > 16 * 1024 * 1024):
                raise ValueError('OpenAppID 压缩包包含不安全或超限的成员')
            seen.add(str(path)); total += member.size
            if total > MAX_EXPANDED: raise ValueError('OpenAppID 解压大小超过限制')
            target = destination.joinpath(*path.parts)
            if member.isdir(): target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, 65536)
                target.chmod(0o644)
    if not (destination / 'odp/appMapping.data').is_file() or not any((destination / 'odp').rglob('*.lua')):
        raise ValueError('OpenAppID 检测器目录不完整')


def detector_md5(data):
    try:
        lines = data.decode('ascii').splitlines()
    except UnicodeDecodeError:
        raise ValueError('OpenAppID 官方校验文件格式无效') from None
    hashes = []
    for line in lines:
        match = re.fullmatch(r'[ \t]*([a-fA-F0-9]{32})[ \t]+\*?snort-openappid\.tar\.gz[ \t]*', line)
        if match:
            hashes.append(match[1].lower())
    if len(hashes) != 1:
        raise ValueError('OpenAppID 官方校验文件格式无效')
    return hashes[0]


def update(lines, root=ROOT):
    root = Path(root)
    previous = snapshot(root)
    if previous is None: return False
    lines.append('检查 OpenAppID 官方检测器更新')
    page = fetch(PAGE).decode('utf-8')
    links = re.findall(r'href=[\"\'](/downloads/openappid/[0-9]+)[\"\']', page)
    if not links: raise ValueError('OpenAppID 官方下载页面未提供检测器包')
    expected = detector_md5(fetch(CHECKSUM, maximum=65536))
    old = previous['receipt'] or {}
    if old.get('md5') == expected:
        atomic_json(root / 'update.json', dict(old, checked=int(time.time())))
        lines.append('OpenAppID 检测器已是当前版本'); return False
    releases = root / 'releases'; releases.mkdir(exist_ok=True)
    # Persistent storage, never the router's memory-backed /tmp.
    with tempfile.TemporaryDirectory(prefix='.download-', dir=releases) as directory:
        stage = Path(directory); archive = stage / 'openappid.tar.gz'
        with archive.open('wb') as handle: fetch('https://www.snort.org' + links[0], handle, MAX_ARCHIVE)
        digest = hashlib.sha256(); legacy = hashlib.md5(usedforsecurity=False)
        with archive.open('rb') as handle:
            while block := handle.read(65536): digest.update(block); legacy.update(block)
        if legacy.hexdigest() != expected: raise ValueError('OpenAppID 官方校验值不匹配')
        identity = digest.hexdigest(); extracted = stage / 'extracted'; extracted.mkdir()
        extract(archive, extracted)
        version = releases / identity
        if version.exists():
            # Reuse only a previously verified immutable release.
            if not (version / '.ndr-sha256').is_file() or (version / '.ndr-sha256').read_text().strip() != identity:
                raise ValueError('OpenAppID 版本目录校验记录不一致')
        else:
            (extracted / 'odp/.ndr-sha256').write_text(identity + '\n')
            (extracted / 'odp').replace(version)
        switch(root, str(version))
        atomic_json(root / 'update.json', dict(sha256=identity, md5=expected, checked=int(time.time()), source='snort.org'))
    lines.append('OpenAppID 检测器已下载并校验，等待引擎热重载')
    return True
