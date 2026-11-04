"""Fetch verified pure Python wheels and produce a deterministic release bundle."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

SOURCES=Path(__file__).with_name('python-sources.json')


def build(target):
    payloads={}
    for spec in json.loads(SOURCES.read_text())['packages']:
        request=urllib.request.Request(spec['url'],headers={'User-Agent':'NDR-build'})
        with urllib.request.urlopen(request,timeout=60) as response:data=response.read(8*1024*1024+1)
        if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=spec['sha256']:
            raise ValueError('Python wheel verification failed: '+spec['name'])
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            for member in wheel.infolist():
                path=Path(member.filename)
                if member.is_dir():continue
                if path.is_absolute() or '..' in path.parts or path.suffix not in ('.py','.txt') and '.dist-info' not in path.parts[0]:
                    raise ValueError('Unexpected Python wheel member')
                if member.file_size>4*1024*1024:raise ValueError('Python wheel member exceeds limit')
                payloads[member.filename]=wheel.read(member)
    # PLY ships an outdated table in the wheel. Generate its current pure
    # Python tables during the build, so the read-only runtime never writes
    # parser caches or spends startup time generating them.
    with tempfile.TemporaryDirectory(prefix='ndr-parser-tables-') as directory:
        root=Path(directory)
        for name,data in payloads.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        result=subprocess.run([sys.executable,'-B','-c','import luqum.parser'],cwd=root,
                              env=dict(os.environ,PYTHONPATH=str(root)),capture_output=True,timeout=30)
        if result.returncode:raise RuntimeError('Could not generate pinned parser tables')
        table=root/'luqum/parsetab.py'
        if not table.is_file():raise RuntimeError('Missing generated parser tables')
        payloads['luqum/parsetab.py']=table.read_bytes()
    target=Path(target)
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as bundle:
        for name,data in sorted(payloads.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644<<16;bundle.writestr(info,data)
    return target


@contextmanager
def environment():
    """Temporary build/test imports; never change the machine's global packages."""
    with tempfile.TemporaryDirectory(prefix='ndr-python-deps-') as directory:
        path=build(Path(directory)/'python-dependencies.zip')
        previous=os.environ.get('NDR_PYTHON_DEPS');os.environ['NDR_PYTHON_DEPS']=str(path)
        try:yield path
        finally:
            if previous is None:os.environ.pop('NDR_PYTHON_DEPS',None)
            else:os.environ['NDR_PYTHON_DEPS']=previous
