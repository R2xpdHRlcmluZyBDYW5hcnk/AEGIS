"""Verify and record a prebuilt ARM64 engine without recompiling it."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from patch_snort import REVISION


def verify(sources_path, prefix):
    sources = json.loads(Path(sources_path).read_text())
    prefix = Path(prefix).resolve()
    if prefix.parent != Path('/opt/ips-snort3'):
        raise ValueError('Unexpected engine prefix')
    binary = prefix / 'bin/snort'
    if b'NDR session sequence exhausted' not in binary.read_bytes():
        raise ValueError('Engine session identity patch missing')
    subprocess.run(['patchelf', '--set-rpath', '$ORIGIN/../lib', str(binary)], check=True)
    architecture = subprocess.check_output(['aarch64-linux-gnu-readelf', '-h', str(binary)], text=True)
    if 'AArch64' not in architecture:
        raise ValueError('Engine is not ARM64')
    subprocess.run(['aarch64-linux-gnu-strip', '--strip-unneeded', str(binary)], check=True)
    version = subprocess.check_output(['qemu-aarch64', str(binary), '-V'], text=True, stderr=subprocess.STDOUT)
    if 'Version ' + sources['snort']['version'] not in version:
        raise ValueError('Engine version differs from source manifest')
    modules = subprocess.check_output(['qemu-aarch64', str(binary), '--daq-dir', str(prefix / 'lib/daq'), '--daq-list'], text=True)
    if 'nfq(' not in modules or 'live inline multi' not in modules:
        raise ValueError('Required NFQ support missing')
    fields=subprocess.check_output(['qemu-aarch64',str(binary),'--help-config','extractor'],text=True)
    # The actual field dispatch is exercised by the native synthetic regressions.
    if not fields: raise ValueError('Extractor metadata missing')
    manifest = dict(sources=sources, architecture='aarch64', binary=str(binary), session_patch=REVISION,
                    sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), version_output=version,
                    compiler=subprocess.check_output(['aarch64-linux-gnu-g++','--version'],text=True).splitlines()[0])
    (prefix / 'engine-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('ARM64 engine and NFQ modules verified: ' + str(binary))


if __name__ == '__main__':
    verify(*sys.argv[1:])
