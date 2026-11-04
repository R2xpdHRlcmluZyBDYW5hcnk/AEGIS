#!/usr/bin/env bash
# Static assets only; engine activation is explicit in deploy-snort3.py.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:---web-only}" != '--web-only' ] || [ "$#" -gt 1 ]; then
    echo 'Use deploy.ps1 -InstallSnort3 -UpdateBackend -EnginePackage for engine activation.' >&2
    exit 2
fi
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }
exec 9>/run/ips-deploy.lock
flock -n 9 || { echo 'Another deployment is running' >&2; exit 1; }
cd "$HERE"
[ -f SHA256SUMS ] || { echo 'Build a release first' >&2; exit 1; }
sha256sum --strict -c SHA256SUMS >/dev/null
exec python3 "$HERE/deploy-angular.py" --release "$HERE"
