"""Verify and record a prebuilt engine without recompiling it."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from patch_snort import REVISION
from engine_platform import elf_architecture,matcher,runner,sources_for,tool_prefix


def verify(sources_path, prefix):
    prefix = Path(prefix).resolve()
    if prefix.parent != Path('/opt/ips-snort3'):
        raise ValueError('Unexpected engine prefix')
    binary = prefix / 'bin/snort'
    arch=elf_architecture(binary)
    sources=sources_for(json.loads(Path(sources_path).read_text()),arch)
    command=runner(arch)+[str(binary)]
    tools=tool_prefix(arch)
    matching=matcher(arch)
    compiled = binary.read_bytes()
    if b'NDR session sequence exhausted' not in compiled:
        raise ValueError('Engine session identity patch missing')
    if b'alert_suppressed' not in compiled:
        raise ValueError('Engine suppressed block logging patch missing')
    if b'NDR_LOGS_REOPENED' not in compiled:
        raise ValueError('Engine event-log reopen barrier missing')
    subprocess.run(['patchelf', '--set-rpath', '$ORIGIN/../lib', str(binary)], check=True)
    subprocess.run([tools+'strip', '--strip-unneeded', str(binary)], check=True)
    version = subprocess.check_output(command+['-V'], text=True, stderr=subprocess.STDOUT)
    if 'Version ' + sources['snort']['version'] not in version:
        raise ValueError('Engine version differs from source manifest')
    if 'Using Hyperscan version ' + sources[matching]['version'] not in version:
        raise ValueError('Pinned matching runtime missing: '+matching)
    plugins=subprocess.check_output(command+['--list-plugins'],text=True)
    if 'search_engine::hyperscan ' not in plugins:
        raise ValueError('Hyperscan search plugin missing')
    modules = subprocess.check_output(command+['--daq-dir', str(prefix / 'lib/daq'), '--daq-list'], text=True)
    if 'nfq(' not in modules or 'live inline multi' not in modules:
        raise ValueError('Required NFQ support missing')
    fields=subprocess.check_output(command+['--help-config','extractor'],text=True)
    # The actual field dispatch is exercised by the native synthetic regressions.
    if not fields: raise ValueError('Extractor metadata missing')
    manifest = dict(sources=sources, architecture=arch, binary=str(binary), session_patch=REVISION,
                    search_engine='hyperscan', matching_library=matching,
                    sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), version_output=version,
                    compiler=subprocess.check_output([tools+'g++','--version'],text=True).splitlines()[0])
    if matching=='vectorscan':manifest['vectorscan_simd']='armv8-neon'
    (prefix / 'engine-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(arch+' engine, '+matching+' and NFQ modules verified: ' + str(binary))


if __name__ == '__main__':
    verify(*sys.argv[1:])
