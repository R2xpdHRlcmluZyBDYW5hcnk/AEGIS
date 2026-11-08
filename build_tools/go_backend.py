"""Build the pinned native console with temporary Go dependencies and caches."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'build_tools/go-sources.json'


@contextmanager
def environment(workspace=None):
    """A caller-owned temporary workspace can be reused across a single test/build run."""
    with tempfile.TemporaryDirectory(prefix='aegis-go-build-') as owned:
        root = Path(workspace or owned).resolve()
        if not root.is_relative_to(Path(tempfile.gettempdir()).resolve()):
            raise ValueError('Go dependencies must stay in the system temporary directory')
        spec = json.loads(SOURCES.read_text())
        candidate = shutil.which('go')
        expected = 'go' + spec['version']
        if candidate:
            version = subprocess.check_output([candidate, 'version'], text=True).split()[2]
            if version != expected:
                candidate = None
        if candidate is None:
            target = 'linux-' + ('arm64' if platform.machine() in ('aarch64', 'arm64') else 'amd64')
            source = spec['archives'][target]
            candidate = root / 'go/bin/go'
            if not candidate.exists():
                archive = root / source['filename']
                request = urllib.request.Request('https://go.dev/dl/' + source['filename'], headers={'User-Agent': 'AEGIS-build'})
                with urllib.request.urlopen(request, timeout=60) as response:
                    with archive.open('wb') as output:
                        shutil.copyfileobj(response, output)
                with archive.open('rb') as downloaded:
                    actual = hashlib.file_digest(downloaded, 'sha256').hexdigest()
                if actual != source['sha256']:
                    raise ValueError('Go toolchain SHA-256 mismatch')
                with tarfile.open(archive) as bundle:
                    bundle.extractall(root, filter='data')
                archive.unlink()
        env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOMODCACHE=str(root/'modules'),
                   GOCACHE=str(root/'cache'), GOPATH=str(root/'gopath'), GOTMPDIR=str(root/'tmp'),
                   GOMAXPROCS='4', CGO_ENABLED='1')
        Path(env['GOTMPDIR']).mkdir(exist_ok=True)
        yield str(candidate), env


def run(arguments, output=None, target='linux-arm64', workspace=None):
    if platform.system() == 'Windows':
        def linux(path):
            return subprocess.check_output(['wsl', '-d', 'Debian', '--', 'wslpath', '-a', str(path).replace('\\', '/')], text=True).strip()
        command = ['wsl', '-d', 'Debian', '--', 'python3', '-B', linux(__file__), '--target', target]
        if output is not None: command += ['--output', linux(output)]
        if workspace: command += ['--workspace', str(workspace)]
        command += ['--', *arguments]
        subprocess.run(command, check=True)
        return
    with environment(workspace) as (go, env):
        if arguments:
            subprocess.run([go, *arguments], cwd=ROOT/'backend', env=env, stdout=sys.stderr, check=True)
        if output is not None:
            output = Path(output).resolve()
            if output.is_relative_to(ROOT):
                raise ValueError('Build output must stay outside the source directory')
            output.parent.mkdir(parents=True, exist_ok=True)
            goos, arch = target.split('-', 1)
            env.update(GOOS=goos, GOARCH=arch, CC='aarch64-linux-gnu-gcc' if arch=='arm64' and platform.machine()!='aarch64' else 'gcc')
            try:
                subprocess.run([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
                                '-o', str(output), './cmd/aegis'], cwd=ROOT/'backend', env=env, stdout=sys.stderr, check=True)
                spec=json.loads(SOURCES.read_text())
                go_license=(Path(go).resolve().parent.parent/'LICENSE').read_text()
                driver_license=(Path(env['GOMODCACHE'])/'github.com/mattn'/('go-sqlite3@'+spec['sqliteDriver']['version'])/'LICENSE').read_text()
                output.with_name(output.name+'.licenses.txt').write_text(
                    'Go '+spec['version']+' https://go.dev/LICENSE\n\n'+go_license+'\n\n'
                    'go-sqlite3 '+spec['sqliteDriver']['version']+' https://github.com/mattn/go-sqlite3\n\n'+driver_license+'\n\n'
                    'SQLite '+spec['sqliteDriver']['sqliteVersion']+' https://sqlite.org/copyright.html\n'
                    'SQLite deliverable code is in the public domain.\n',encoding='utf-8')
            except BaseException:
                output.unlink(missing_ok=True)
                output.with_name(output.name+'.licenses.txt').unlink(missing_ok=True)
                raise


def release(directory):
    """Build one multicall executable; deployment retains the existing service names."""
    directory = Path(directory)
    names = ('ips-web', 'ips-rule-manager', 'ips-event-bridge', 'ips-snort-rules')
    target = directory / names[0]
    run(['test', '-count=1', '-timeout=120s', './...'], target)
    for name in names[1:]:
        shutil.copy2(target, directory / name)
    target.with_name(target.name+'.licenses.txt').replace(directory/'backend-licenses.txt')
    spec = json.loads(SOURCES.read_text())
    manifest = dict(schema=1, backend='go', go_version=spec['version'], target='linux-arm64',
                    sqlite_version=spec['sqliteDriver']['sqliteVersion'],
                    files={name: hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in names})
    (directory/'backend-build.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    return (*names, 'backend-build.json','backend-licenses.txt')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--target', default='linux-arm64')
    parser.add_argument('--workspace')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    run(args.arguments[1:] if args.arguments[:1]==['--'] else args.arguments,
        args.output, args.target, args.workspace)
