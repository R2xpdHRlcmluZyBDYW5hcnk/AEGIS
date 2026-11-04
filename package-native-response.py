"""Build a small ARM64 response adapter in WSL, without rebuilding Snort."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parent


def build(output):
    output=Path(output).resolve()
    if output.is_relative_to(ROOT):raise ValueError('Export native binaries outside the source tree')
    with tempfile.TemporaryDirectory(prefix='ips-response-build-') as tmp:
        library=Path(tmp)/'libips-response.so'
        compiler='aarch64-linux-gnu-gcc'
        flags=['-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now']
        subprocess.run([compiler,*flags,'-o',str(library),str(ROOT/'native_response.c'),'-ldl','-pthread'],check=True)
        binary=library.read_bytes()
        if binary[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(binary[18:20],'little')!=183:raise ValueError('Expected ARM64 ELF')
        payload={'libips-response.so':binary,'native_response.c':(ROOT/'native_response.c').read_bytes(),
                 'deploy-native-response.py':(ROOT/'deploy-native-response.py').read_bytes()}
        metadata=dict(revision=1,architecture='aarch64',compiler=subprocess.check_output([compiler,'-dumpfullversion'],text=True).strip(),
            flags=flags,sha256={name:hashlib.sha256(value).hexdigest() for name,value in payload.items()})
        payload['manifest.json']=(json.dumps(metadata,indent=2)+'\n').encode()
        payload['SHA256SUMS']=''.join(hashlib.sha256(value).hexdigest()+'  '+name+'\n' for name,value in sorted(payload.items())).encode()
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            for name,value in sorted(payload.items()):
                info=tarfile.TarInfo('response/'+name);info.size=len(value);info.mode=0o644;archive.addfile(info,io.BytesIO(value))
        output.mkdir(parents=True,exist_ok=True)
        target=output/'ips-native-response-arm64-1.tar.gz';target.write_bytes(gzip.compress(stream.getvalue(),mtime=0))
        target.with_suffix('.gz.sha256').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+'  '+target.name+'\n')
        print(target)
        return target


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True)
    build(parser.parse_args().output)
