"""Cross-build the extension against the pinned, session-patched Snort layout.

Run in the Debian build environment prepared by build-snort3-arm64.sh. All
downloaded headers and compiler output remain in temporary/export directories.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build_tools'))
from patch_snort import patch, REVISION


def build(output, engine, prefix='/opt/ips-snort3/3.12.4.0', archive=None):
    output = Path(output).resolve(); engine = Path(engine)
    if output.is_relative_to(ROOT): raise ValueError('Export outside the source directory')
    spec = json.loads((ROOT / 'build_tools/snort-sources.json').read_text())['snort']
    compiler = shutil.which('aarch64-linux-gnu-g++')
    if not compiler: raise RuntimeError('Prepare the pinned ARM64 engine build environment first')
    with tempfile.TemporaryDirectory(prefix='ndr-session-build-') as directory:
        work = Path(directory); source = Path(archive) if archive else work / 'snort.tar.gz'
        if archive is None:
            with urllib.request.urlopen(spec['url'], timeout=120) as response, source.open('wb') as handle:
                shutil.copyfileobj(response, handle)
        if hashlib.sha256(source.read_bytes()).hexdigest() != spec['sha256']:
            raise ValueError('Snort source checksum differs')
        with tarfile.open(source) as package: package.extractall(work / 'src', filter='data')
        headers = work / 'src' / ('snort3-' + spec['version']); patch(headers)
        output.mkdir(parents=True, exist_ok=True)
        library = output / 'ndr_session.so'
        args = [compiler, '-DHAVE_VISIBILITY', '-std=c++17', '-O2', '-fPIC', '-shared', '-fvisibility=hidden']
        for include in (headers/'src', headers/'src/network_inspectors', Path(prefix)/'include/snort', Path(prefix)/'include',
                        Path('/usr/include/luajit-2.1'), Path('/usr/include/aarch64-linux-gnu')):
            args += ['-I', str(include)]
        subprocess.run(args + ['-o', str(library), str(ROOT/'native_session_logger.cc')], check=True)
        manifest = dict(version=1, snort=spec, session_patch=REVISION,
                        source_sha256=hashlib.sha256((ROOT/'native_session_logger.cc').read_bytes().replace(b'\r\n',b'\n')).hexdigest(),
                        engine_sha256=hashlib.sha256(engine.read_bytes()).hexdigest(),
                        sha256=hashlib.sha256(library.read_bytes()).hexdigest())
        (output/'session-logger.json').write_text(json.dumps(manifest, indent=2)+'\n')
        for name in ('native_session_logger.cc', 'LICENSES/GPL-2.0.txt', 'LICENSES/Snort-COPYING.txt'):
            shutil.copy2(ROOT/name, output/Path(name).name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True); parser.add_argument('--engine', required=True)
    parser.add_argument('--prefix', default='/opt/ips-snort3/3.12.4.0'); parser.add_argument('--archive')
    args = parser.parse_args(); build(args.output, args.engine, args.prefix, args.archive)
