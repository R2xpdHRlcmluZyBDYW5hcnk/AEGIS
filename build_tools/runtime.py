import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

TOOLCHAIN = json.loads(Path(__file__).with_name('toolchain-sources.json').read_text(encoding='utf-8'))
NODE_VERSION = TOOLCHAIN['node']['version']
NPM_VERSION = TOOLCHAIN['npm']['version']


def download(url, target, expected=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'AEGIS-build'})
    with urllib.request.urlopen(request, timeout=90) as response, target.open('wb') as output:
        shutil.copyfileobj(response, output)
    if expected and hashlib.sha256(target.read_bytes()).hexdigest() != expected:
        target.unlink()
        raise RuntimeError('Download checksum mismatch: ' + url)
    return target


def compatible(node):
    try:
        value = subprocess.check_output([str(node), '--version'], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return False
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', value)
    if not match:
        return False
    version = tuple(map(int, match.groups()))
    minimum = tuple(map(int, NODE_VERSION.split('.')))
    return version[0] == minimum[0] and version >= minimum


def npm_cli(node):
    candidates = [node.parent / 'node_modules/npm/bin/npm-cli.js',
                  node.parent.parent / 'lib/node_modules/npm/bin/npm-cli.js']
    for executable in ('npm.cmd', 'npm', 'npm.ps1'):
        found = shutil.which(executable)
        if found:
            candidates.append(Path(found).resolve().parent / 'node_modules/npm/bin/npm-cli.js')
            candidates.append(Path(found).resolve().parent.parent / 'lib/node_modules/npm/bin/npm-cli.js')
    return next((path for path in candidates if path.is_file()), None)


def compatible_npm(cli):
    try:
        version = json.loads((cli.parent.parent / 'package.json').read_text(encoding='utf-8'))['version']
        if not re.fullmatch(r'\d+\.\d+\.\d+', version):
            return False
        current = tuple(map(int, version.split('.')))
        minimum = tuple(map(int, NPM_VERSION.split('.')))
        return current[0] == minimum[0] and current >= minimum
    except (OSError, ValueError, KeyError, TypeError):
        return False


def npm_toolchain(node, work):
    cli = npm_cli(node)
    if cli and compatible_npm(cli):
        return cli
    spec = TOOLCHAIN['npm']
    print('Downloading temporary npm ' + NPM_VERSION, file=sys.stderr, flush=True)
    archive = download(spec['tarball'], work / 'npm.tgz')
    try:
        algorithm, encoded = spec['integrity'].split('-', 1)
        if algorithm != 'sha512' or hashlib.sha512(archive.read_bytes()).digest() != base64.b64decode(encoded, validate=True):
            raise RuntimeError('npm archive checksum mismatch')
    except BaseException:
        archive.unlink(missing_ok=True)
        raise
    destination = work / 'npm-toolchain'
    destination.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(destination, filter='data')
    cli = destination / 'package/bin/npm-cli.js'
    if not cli.is_file() or not compatible_npm(cli):
        raise RuntimeError('Downloaded npm installation is incomplete')
    return cli


def toolchain(work):
    override = os.environ.get('NDR_NODE')
    candidate = override or shutil.which('node')
    if candidate:
        node = Path(candidate).resolve()
        if compatible(node):
            return node, npm_toolchain(node, work)
        if override:
            raise RuntimeError('NDR_NODE must point to stable Node.js ' + NODE_VERSION + ' or newer in the same LTS major')
    system = {'Windows': 'win', 'Linux': 'linux', 'Darwin': 'darwin'}.get(platform.system())
    arch = {'amd64': 'x64', 'x86_64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if not system or not arch:
        raise RuntimeError('Install a supported stable Node.js and npm, or set NDR_NODE')
    base = f'https://nodejs.org/dist/v{NODE_VERSION}/'
    folder = f'node-v{NODE_VERSION}-{system}-{arch}'
    name = folder + ('.zip' if system == 'win' else '.tar.xz')
    print('Downloading temporary Node.js ' + NODE_VERSION, file=sys.stderr, flush=True)
    sums = download(base + 'SHASUMS256.txt', work / 'node-checksums.txt').read_text()
    checksum = next((line.split()[0] for line in sums.splitlines() if line.split()[-1] == name), None)
    if not checksum:
        raise RuntimeError('Node.js archive is not listed in official checksums')
    archive = download(base + name, work / name, checksum)
    if system == 'win':
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                if not (work / item.filename).resolve().is_relative_to(work.resolve()):
                    raise RuntimeError('Unsafe Node.js archive path')
            package.extractall(work)
        node = work / folder / 'node.exe'
        cli = work / folder / 'node_modules/npm/bin/npm-cli.js'
    else:
        with tarfile.open(archive) as package:
            package.extractall(work, filter='data')
        node = work / folder / 'bin/node'
        cli = work / folder / 'lib/node_modules/npm/bin/npm-cli.js'
    if not compatible(node):
        raise RuntimeError('Downloaded Node.js installation is incomplete')
    return node, npm_toolchain(node, work)


def environment(node, work):
    env = {key: value for key, value in os.environ.items() if key.upper() not in ('PATH', 'NPM_CONFIG_CACHE')}
    env.update(PATH=str(node.parent) + os.pathsep + os.environ.get('PATH', ''),
               npm_config_cache=str(work / 'npm-cache'), NG_CLI_ANALYTICS='false',
               PYTHONDONTWRITEBYTECODE='1', CI='1')
    return env
