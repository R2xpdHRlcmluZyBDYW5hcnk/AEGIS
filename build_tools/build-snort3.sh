#!/bin/bash
# Build pinned Linux engines without putting downloads or outputs in the source tree.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONDONTWRITEBYTECODE=1
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
arch=${SNORT_ENGINE_ARCH:-$(uname -m)}
case "$arch" in arm64|aarch64) arch=aarch64; matching=vectorscan; triplet=aarch64-linux-gnu; cc=aarch64-linux-gnu-gcc; cxx=aarch64-linux-gnu-g++;;
    amd64|x86_64) arch=x86_64; matching=hyperscan; triplet=x86_64-linux-gnu; cc=gcc; cxx=g++;;
    *) echo 'Supported engine targets are aarch64 and x86_64' >&2; exit 1;; esac
if [ "$arch" = x86_64 ] && [ "$(uname -m)" != x86_64 ]; then
    echo 'Build the x86-64 engine on an x86-64 Linux host' >&2; exit 1
fi
version=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["snort"]["version"])' "$project/build_tools/snort-sources.json")
work=${SNORT_BUILD_WORK:-$(mktemp -d /var/tmp/ips-snort3-build-XXXXXX)}
prefix=${SNORT_ENGINE_PREFIX:-/opt/ips-snort3/$version-$arch}
python3 - "$work" "$prefix" <<'PY'
from pathlib import Path
import sys
work,prefix=map(Path,sys.argv[1:])
if work.resolve().parent!=Path('/var/tmp') or not work.name.startswith('ips-snort3-'):
    raise SystemExit('Build workspace must be /var/tmp/ips-snort3-*')
if prefix.resolve().parent!=Path('/opt/ips-snort3'):
    raise SystemExit('Engine prefix must be /opt/ips-snort3/<version>')
PY
if [ -z "${SNORT_BUILD_WORK:-}" ]; then
    cleanup() {
        resolved=$(realpath -- "$work")
        case "$resolved" in /var/tmp/ips-snort3-build-*) rm -rf -- "$resolved";; *) echo 'Refusing unexpected build cleanup path' >&2;; esac
    }
    trap cleanup EXIT
fi
mkdir -p "$work/src" "$work/logs" "$prefix"
sources="$work/engine-sources.json"
python3 "$project/build_tools/engine_platform.py" "$project/build_tools/snort-sources.json" "$arch" "$sources"
daq_version=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["libdaq"]["version"])' "$sources")
matching_version=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]]["version"])' "$sources" "$matching")
if [ "${1:-}" = '--verify-existing' ]; then
    python3 "$project/build_tools/verify_snort3.py" "$sources" "$prefix"; exit 0
fi
if [ -x "$prefix/bin/snort" ] && [ -f "$prefix/engine-manifest.json" ]; then
    python3 - "$sources" "$prefix/engine-manifest.json" "$project/build_tools" <<'PY'
import hashlib,json,sys
sys.path.insert(0,sys.argv[3])
from patch_snort import REVISION
expected,actual=(json.load(open(p)) for p in sys.argv[1:3])
if actual.get('session_patch')!=REVISION or actual.get('sources')!=expected:
    raise SystemExit('Existing engine sources or session patch differ; select a separate prefix')
if hashlib.sha256(open(actual['binary'],'rb').read()).hexdigest()!=actual['sha256']:
    raise SystemExit('Existing engine checksum differs; refusing to reuse')
print('Reusing pinned '+expected['target']['architecture']+' engine: '+actual['binary'])
PY
    exit 0
fi
python3 "$project/build_tools/prepare_engine_runtime.py" "$sources" "$work" "$prefix"
python3 - "$sources" "$work" "$matching" <<'PY'
import hashlib,json,pathlib,shutil,sys,tarfile,urllib.request
manifest,root=json.load(open(sys.argv[1])),pathlib.Path(sys.argv[2])
for key in ('libdaq','snort',sys.argv[3]):
    spec=manifest[key];archive=root/(key+'.tar.gz')
    if not archive.exists():
        request=urllib.request.Request(spec['url'],headers={'User-Agent':'IPS-engine-build'})
        with urllib.request.urlopen(request,timeout=120) as source,archive.open('wb') as output:shutil.copyfileobj(source,output)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=spec['sha256']:raise SystemExit('Source checksum mismatch: '+key)
    with tarfile.open(archive) as package:package.extractall(root/'src',filter='data')
PY
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig:/usr/lib/$triplet/pkgconfig:/usr/share/pkgconfig"
export CC=$cc CXX=$cxx
toolchain="$work/toolchain.cmake"
cat > "$toolchain" <<CMAKE
set(CMAKE_C_COMPILER $cc)
set(CMAKE_CXX_COMPILER $cxx)
set(CMAKE_LIBRARY_ARCHITECTURE $triplet)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
CMAKE
if [ "$arch" = aarch64 ]; then
    cat >> "$toolchain" <<'CMAKE'
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_IGNORE_PATH /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu)
set(CMAKE_CROSSCOMPILING_EMULATOR /usr/bin/qemu-aarch64)
CMAKE
    matching_source="$work/src/vectorscan-vectorscan-$matching_version"
    matching_options=(-DBUILD_STATIC_LIBS=OFF -DBUILD_UNIT=OFF -DBUILD_TOOLS=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_DOC=OFF
        -DFAT_RUNTIME=OFF -DUSE_CPU_NATIVE=OFF -DBUILD_SVE=OFF -DBUILD_SVE2=OFF -DBUILD_SVE2_BITPERM=OFF)
else
    echo 'set(CMAKE_IGNORE_PATH /usr/lib/aarch64-linux-gnu /lib/aarch64-linux-gnu)' >> "$toolchain"
    matching_source="$work/src/hyperscan-$matching_version"
    # SSSE3/SSE4.2/AVX2 runtime dispatch; do not bind artifacts to this host CPU.
    matching_options=(-DFAT_RUNTIME=ON -DBUILD_STATIC_AND_SHARED=OFF -DBUILD_AVX512=OFF -DBUILD_AVX512VBMI=OFF -DBUILD_CHIMERA=OFF)
fi
cmake -S "$matching_source" -B "$work/matching-build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON -DBUILD_EXAMPLES=OFF \
    "${matching_options[@]}" > "$work/logs/matching-configure.log" 2>&1 || { tail -n 70 "$work/logs/matching-configure.log"; exit 1; }
cmake --build "$work/matching-build" --parallel 8 --target hs_shared hs_runtime_shared > "$work/logs/matching-build.log" 2>&1 || { tail -n 60 "$work/logs/matching-build.log"; exit 1; }
cmake --install "$work/matching-build" > "$work/logs/matching-install.log" 2>&1
daq="$work/src/libdaq-$daq_version";snort="$work/src/snort3-$version"
python3 "$project/build_tools/patch_snort.py" "$snort"
(
    cd "$daq";autoreconf -fi
    ./configure --host="$triplet" --prefix="$prefix" --disable-static \
        --enable-nfq-module --disable-netmap-module --disable-divert-module \
        --with-libpcap-includes=/usr/include --with-libpcap-libraries="/usr/lib/$triplet"
    make -j8;make install
) > "$work/logs/libdaq-build.log" 2>&1 || { tail -n 60 "$work/logs/libdaq-build.log"; exit 1; }
cmake -S "$snort" -B "$work/snort-build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$toolchain" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_PREFIX_PATH="$prefix;/usr" -DCMAKE_LIBRARY_PATH="/usr/lib/$triplet" \
    -DCMAKE_INSTALL_RPATH="$prefix/lib" -DENABLE_SHELL=ON -DMAKE_DOC=OFF \
    -DCMAKE_DISABLE_FIND_PACKAGE_Asciidoc=ON -DCMAKE_DISABLE_FIND_PACKAGE_DBLATEX=ON -DCMAKE_DISABLE_FIND_PACKAGE_Ruby=ON \
    -DENABLE_UNIT_TESTS=OFF -DENABLE_STATIC_DAQ=OFF \
    -DHS_INCLUDE_DIR="$prefix/include/hs" -DHS_LIBRARIES_DIR="$prefix/lib" \
    -DDAQ_INCLUDE_DIR_HINT="$prefix/include" -DDAQ_LIBRARIES_DIR_HINT="$prefix/lib" \
    > "$work/logs/snort-configure.log" 2>&1 || { tail -n 70 "$work/logs/snort-configure.log"; exit 1; }
cmake --build "$work/snort-build" --parallel 8 > "$work/logs/snort-build.log" 2>&1 || { tail -n 60 "$work/logs/snort-build.log"; exit 1; }
cmake --install "$work/snort-build" > "$work/logs/snort-install.log" 2>&1
python3 "$project/build_tools/prepare_engine_runtime.py" "$sources" "$work" "$prefix"
python3 "$project/build_tools/verify_snort3.py" "$sources" "$prefix"
