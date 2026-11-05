"""Build the optional ARM64 SQLite library used only by the Web service."""
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

VERSION = '3.54.1'
ARCHIVE = 'sqlite-amalgamation-3540100'
SOURCE_SHA3 = '92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30'
RUNTIME = 'libsqlite3-ndr.so'


def build(output):
    compiler = shutil.which('aarch64-linux-gnu-gcc')
    if not compiler:
        raise RuntimeError('Prepare the Debian ARM64 cross-build environment from README-deploy.md')
    with urllib.request.urlopen(f'https://sqlite.org/2026/{ARCHIVE}.zip', timeout=45) as response:
        archive = response.read(8 * 1024 * 1024 + 1)
    if hashlib.sha3_256(archive).hexdigest() != SOURCE_SHA3:
        raise ValueError('SQLite source SHA3-256 differs from the pinned official digest')
    with tempfile.TemporaryDirectory(prefix='ndr-sqlite-source-') as directory:
        source = Path(directory) / 'sqlite3.c'
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            source.write_bytes(bundle.read(f'{ARCHIVE}/sqlite3.c'))
        options = ('THREADSAFE=1', 'ENABLE_COLUMN_METADATA', 'ENABLE_DBSTAT_VTAB',
                   'ENABLE_FTS5', 'ENABLE_RTREE', 'ENABLE_MATH_FUNCTIONS', 'ENABLE_UNLOCK_NOTIFY')
        subprocess.run([compiler, '-O2', '-fPIC', '-shared', '-Wl,-soname,libsqlite3.so.0',
                        *('-DSQLITE_'+option for option in options), str(source), '-o', str(Path(output)/RUNTIME),
                        '-pthread', '-ldl', '-lm'], check=True)
