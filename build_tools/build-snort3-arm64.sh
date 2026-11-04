#!/bin/bash
# Cross-build the pinned engine in WSL. No generated files enter the source tree.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONDONTWRITEBYTECODE=1
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=${SNORT_BUILD_WORK:-/var/tmp/ips-snort3-build}
prefix=${SNORT_ENGINE_PREFIX:-/opt/ips-snort3/3.12.4.0}
case "$work" in /var/tmp/ips-snort3-*) ;; *) echo 'Build workspace must be /var/tmp/ips-snort3-*' >&2; exit 1;; esac
case "$prefix" in /opt/ips-snort3/*) ;; *) echo 'Engine prefix must be /opt/ips-snort3/<version>' >&2; exit 1;; esac
mkdir -p "$work/src" "$work/logs" "$prefix"
python3 "$project/build_tools/prepare_engine_runtime.py" "$project/build_tools/snort-sources.json" "$work" "$prefix"
if [ "${1:-}" = '--verify-existing' ]; then
    exec python3 "$project/build_tools/verify_snort3.py" "$project/build_tools/snort-sources.json" "$prefix"
fi
if [ -x "$prefix/bin/snort" ] && [ -f "$prefix/engine-manifest.json" ]; then
    python3 - "$project/build_tools/snort-sources.json" "$prefix/engine-manifest.json" "$project/build_tools" <<'PY'
import hashlib, json, sys
sys.path.insert(0,sys.argv[3])
from patch_snort import REVISION
expected, actual = (json.load(open(p)) for p in sys.argv[1:3])
if actual.get('session_patch') != REVISION:
    raise SystemExit('Existing engine session patch differs; select a separate prefix')
if any(actual['sources'].get(key) != expected[key] for key in ('snort','libdaq','target')):
    raise SystemExit('Existing engine source manifest differs; select a separate prefix')
if hashlib.sha256(open(actual['binary'],'rb').read()).hexdigest() != actual['sha256']:
    raise SystemExit('Existing engine checksum differs; refusing to reuse')
print('Reusing pinned ARM64 engine: ' + actual['binary'])
PY
    exit 0
fi
python3 - "$project/build_tools/snort-sources.json" "$work" <<'PY'
import hashlib, json, pathlib, shutil, sys, tarfile, urllib.request
manifest, root = json.load(open(sys.argv[1])), pathlib.Path(sys.argv[2])
for key in ('libdaq', 'snort'):
    spec = manifest[key]
    archive = root / (key + '.tar.gz')
    if not archive.exists():
        request = urllib.request.Request(spec['url'], headers={'User-Agent': 'IPS-engine-build'})
        with urllib.request.urlopen(request, timeout=120) as source, archive.open('wb') as output:
            shutil.copyfileobj(source, output)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
        raise SystemExit('Source checksum mismatch: ' + key)
    with tarfile.open(archive) as package:
        package.extractall(root / 'src', filter='data')
PY
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig"
export CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++
daq="$work/src/libdaq-3.0.28"
snort="$work/src/snort3-3.12.4.0"
python3 "$project/build_tools/patch_snort.py" "$snort"
(
    cd "$daq"
    autoreconf -fi
    ./configure --host=aarch64-linux-gnu --prefix="$prefix" --disable-static \
        --enable-nfq-module --disable-netmap-module --disable-divert-module \
        --with-libpcap-includes=/usr/include --with-libpcap-libraries=/usr/lib/aarch64-linux-gnu
    make -j8
    make install
) > "$work/logs/libdaq-build.log" 2>&1 || { tail -n 60 "$work/logs/libdaq-build.log"; exit 1; }
cat > "$work/arm64.cmake" <<'CMAKE'
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)
set(CMAKE_IGNORE_PATH /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_CROSSCOMPILING_EMULATOR /usr/bin/qemu-aarch64)
CMAKE
cmake -S "$snort" -B "$work/snort-build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$work/arm64.cmake" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_PREFIX_PATH="$prefix;/usr" -DCMAKE_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu \
    -DCMAKE_INSTALL_RPATH="$prefix/lib" -DENABLE_SHELL=ON -DMAKE_DOC=OFF \
    -DCMAKE_DISABLE_FIND_PACKAGE_Asciidoc=ON -DCMAKE_DISABLE_FIND_PACKAGE_DBLATEX=ON -DCMAKE_DISABLE_FIND_PACKAGE_Ruby=ON \
    -DENABLE_UNIT_TESTS=OFF -DENABLE_STATIC_DAQ=OFF \
    -DDAQ_INCLUDE_DIR_HINT="$prefix/include" -DDAQ_LIBRARIES_DIR_HINT="$prefix/lib" \
    > "$work/logs/snort-configure.log" 2>&1 || { tail -n 70 "$work/logs/snort-configure.log"; exit 1; }
cmake --build "$work/snort-build" --parallel 8 > "$work/logs/snort-build.log" 2>&1 || { tail -n 60 "$work/logs/snort-build.log"; exit 1; }
cmake --install "$work/snort-build" > "$work/logs/snort-install.log" 2>&1
python3 "$project/build_tools/verify_snort3.py" "$project/build_tools/snort-sources.json" "$prefix"
