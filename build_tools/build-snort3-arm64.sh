#!/bin/bash
# Preserve the established ARM64 build entry point and SDK location.
set -euo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["snort"]["version"])' "$project/build_tools/snort-sources.json")
export SNORT_ENGINE_ARCH=aarch64
export SNORT_ENGINE_PREFIX=${SNORT_ENGINE_PREFIX:-/opt/ips-snort3/$version}
exec bash "$project/build_tools/build-snort3.sh" "$@"
