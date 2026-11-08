"""Run the production UI against the real Go handlers and synthetic fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from build_tools.runtime import environment,toolchain
from preview import native_fixture_command


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--go-workspace',help='Optional existing temporary Go build workspace')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='aegis-browser-') as directory:
        work=Path(directory);static=work/'static';static.mkdir()
        with tarfile.open(args.release) as archive:
            manifest=json.load(archive.extractfile('snort-ndr/frontend-build.json'))
            for name,digest in manifest['files'].items():
                if Path(name).name!=name:raise ValueError('Unexpected static member')
                data=archive.extractfile('snort-ndr/'+name).read()
                if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Static checksum differs')
                (static/name).write_bytes(data)
        (static/'frontend-build.json').write_text(json.dumps(manifest))
        (static/'favicon.svg').write_bytes((ROOT/'favicon.svg').read_bytes())
        stop=work/'stop';command,env=native_fixture_command(static,stop,19096)
        if args.go_workspace:
            index=max(i for i,value in enumerate(command) if value=='--');command[index:index]=['--workspace',args.go_workspace]
        node,_=toolchain(work);env.update(environment(node,work),NDR_PREVIEW_URL='http://127.0.0.1:19096')
        options=dict(creationflags=subprocess.CREATE_NO_WINDOW) if os.name=='nt' else {}
        with (work/'fixture.log').open('w') as log:
            process=subprocess.Popen(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,**options)
            try:
                for _ in range(1800):
                    if process.poll() is not None:raise RuntimeError((work/'fixture.log').read_text()[-4000:])
                    try:
                        urllib.request.urlopen(env['NDR_PREVIEW_URL']+'/login',timeout=.5).close();break
                    except OSError:time.sleep(.2)
                else:raise TimeoutError('Go fixture did not become ready')
                result=subprocess.run([str(node),str(ROOT/'tests/angular-go-backend.mjs')],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180,**options)
                print(result.stdout,flush=True)
                result.check_returncode()
            finally:
                stop.touch()
                try:process.wait(timeout=20)
                except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=10)


if __name__=='__main__':main()
