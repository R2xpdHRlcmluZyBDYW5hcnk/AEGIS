#!/bin/bash
set -euo pipefail
export SNORT_ENGINE_ARCH=x86_64
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/build-snort3.sh" "$@"
