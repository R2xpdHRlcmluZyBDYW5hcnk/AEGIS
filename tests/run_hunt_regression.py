"""Desktop browser checks for search, AppID rendering and cancellable inference."""
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
from build_tools.python_dependencies import environment as dependencies
from build_tools.runtime import toolchain,environment


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--search-only',action='store_true',help='Skip the independent inference regression')
    args=parser.parse_args()
    with dependencies(),tempfile.TemporaryDirectory(prefix='ndr-hunt-browser-') as directory:
        root=Path(directory);static=root/'static';static.mkdir()
        with tarfile.open(args.release) as archive:
            manifest=json.load(archive.extractfile('snort-ndr/frontend-build.json'))
            for name,digest in manifest['files'].items():
                if Path(name).name!=name:raise ValueError('Unexpected static asset name')
                data=archive.extractfile('snort-ndr/'+name).read()
                if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Static asset checksum differs')
                (static/name).write_bytes(data)
        (static/'frontend-build.json').write_text(json.dumps(manifest))
        node,_=toolchain(root);env=environment(node,root);stop=root/'stop'
        env.update(NDR_PREVIEW_STATIC_DIR=str(static),NDR_PREVIEW_AI='1',NDR_PREVIEW_SESSION='1',NDR_PREVIEW_PAGING='1',
                   NDR_PREVIEW_STOP_FILE=str(stop),NDR_TEST_OUTPUT=str(root/'screenshots'))
        with (root/'preview.log').open('w') as log:
            server=subprocess.Popen([sys.executable,'-B',str(ROOT/'tests/serve_preview.py')],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if server.poll() is not None:raise RuntimeError((root/'preview.log').read_text()[-4000:])
                    try:
                        urllib.request.urlopen('http://127.0.0.1:19090/login',timeout=.5).close();break
                    except OSError:time.sleep(.1)
                else:raise RuntimeError('Synthetic preview did not start')
                scripts=('angular-hunt-suggestions.mjs',) if args.search_only else ('angular-local-llm.mjs','angular-hunt-suggestions.mjs')
                for script in scripts:
                    print('RUN '+script,flush=True)
                    subprocess.run([str(node),str(ROOT/'tests'/script)],cwd=ROOT,env=env,check=True,timeout=180)
            finally:
                stop.touch()
                try:server.wait(timeout=15)
                except subprocess.TimeoutExpired:server.terminate();server.wait(timeout=5)


if __name__=='__main__':main()
