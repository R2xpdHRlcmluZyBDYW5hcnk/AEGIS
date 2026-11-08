"""Export the prebuilt ARM64 runtime separately from the console release."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
# Stable deployed location shared by existing units, wrappers and rollback tools.
PREFIX=Path('/opt/ips-snort3/3.12.4.0')
ROOT=Path(__file__).resolve().parents[1]
SOURCE_PREFIX=Path('/opt/ips-snort3')/json.loads((ROOT/'build_tools/snort-sources.json').read_text())['snort']['version']


def build(output,prefix=None):
    prefix=Path(prefix or SOURCE_PREFIX).resolve()
    if prefix.parent!=Path('/opt/ips-snort3'):
        raise ValueError('Unexpected engine prefix')
    output=Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('Export engine packages outside the source directory')
    manifest=json.loads((prefix/'engine-manifest.json').read_text())
    if manifest['architecture']!='aarch64' or hashlib.sha256((prefix/'bin/snort').read_bytes()).hexdigest()!=manifest['sha256']:
        raise ValueError('Prebuilt engine verification failed')
    files=set()
    for base in (prefix/'bin',prefix/'lib/daq',prefix/'etc/snort',prefix/'share/appid',prefix/'share/licenses'):
        if base.exists():
            files.update(path for path in base.rglob('*') if path.is_file() or path.is_symlink())
    files.update(prefix.glob('lib/libdaq.so*'))
    files.update(prefix.glob('lib/libhs.so*'))
    files.add(prefix/'engine-manifest.json')
    checksums={}
    output.mkdir(parents=True,exist_ok=True)
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as package:
        for path in sorted(files):
            # SDK tools are unrelated to normal runtime updates.
            if path.parent==prefix/'bin' and path.name!='snort':
                continue
            mapped=PREFIX/path.relative_to(prefix) if path.is_relative_to(prefix) else path
            name=mapped.relative_to('/').as_posix()
            info=tarfile.TarInfo(name);info.mtime=0
            if path.is_symlink():
                target=path.readlink()
                if target.is_absolute() or '..' in target.parts:
                    raise ValueError('Unsafe runtime link')
                info.type=tarfile.SYMTYPE;info.linkname=str(target);info.mode=0o777
                package.addfile(info)
            else:
                if path==prefix/'engine-manifest.json':
                    data=(json.dumps(dict(manifest,binary=str(PREFIX/'bin/snort')),indent=2)+'\n').encode()
                else:
                    data=path.read_bytes()
                info.size=len(data)
                info.mode=0o755 if path.name=='snort' or path.suffix=='.so' else 0o644
                package.addfile(info,io.BytesIO(data))
                checksums[name]=hashlib.sha256(data).hexdigest()
        if manifest.get('session_patch'):
            name=str(PREFIX/'share/licenses/ndr-session/patch_snort.py').lstrip('/')
            data=(ROOT/'build_tools/patch_snort.py').read_bytes()
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
            package.addfile(info,io.BytesIO(data));checksums[name]=hashlib.sha256(data).hexdigest()
        sums=json.dumps(checksums,sort_keys=True,indent=2).encode()+b'\n'
        info=tarfile.TarInfo('ENGINE_SHA256SUMS.json');info.size=len(sums);info.mode=0o644
        package.addfile(info,io.BytesIO(sums))
    suffix={'ndr-session-1':'-session1','ndr-session-2':'-session2','ndr-session-3':'-session3'}.get(manifest.get('session_patch'),'')
    archive=output/('ips-snort3-arm64-'+manifest['sources']['snort']['version']+suffix+'.tar.gz')
    archive.write_bytes(gzip.compress(stream.getvalue(),mtime=0))
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.gz.sha256').write_text(digest+'  '+archive.name+'\n')
    print(archive)
    return archive


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--prefix',default=str(SOURCE_PREFIX))
    args=parser.parse_args()
    build(args.output,args.prefix)
