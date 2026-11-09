#!/usr/bin/env python3
"""Deterministic source release; never glob the workspace or router state."""
import gzip
import argparse
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import sys
import subprocess
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
FILES = '''AGENTS.md
LICENSE
LICENSES/GPL-2.0.txt
LICENSES/Snort-COPYING.txt
README-deploy.md
README.md
THIRD_PARTY_NOTICES.md
action-override.conf
build_frontend.py
deploy-angular.py
deploy-backend.py
deploy-native-backend.py
deploy-postgresql.py
deploy-native-response.py
deploy-nft.py
deploy-quic-observer.py
deploy-session-engine.py
deploy-session-logger.py
deploy-snort-config.py
deploy-snort3.py
deploy-supervisor.py
deploy.ps1
deploy.sh
deployment_layout.py
deployment_support.py
disable.conf
docs/dependency-policy.md
docs/event-search.md
docs/go-runtime.md
docs/history-management.md
docs/hunt-state-values.md
docs/license-sources.md
docs/local-llm.md
docs/log-storage.md
docs/native-response.md
docs/ndr-observability.md
docs/nfqueue-rules.md
docs/parallel-processing.md
docs/quic-observer.md
docs/rule-management.md
docs/rule-policy.md
docs/rule-source-verification.md
docs/snort3-engine.md
docs/sqlite-recovery.md
drop.conf
favicon.svg
home-net.lua
ips-event-bridge.service
ips-log-maintenance
ips-log-maintenance.service
ips-log-maintenance.timer
ips-quic-observer.service
ips-restore.conf
ips-rule-manager.service
ips-web-bans.lua
ips-web-hunting.rules
ips-web-isolated.conf
ips-web.conf
ips-web.service
ips.service
local.rules
logrotate-snort
modify.conf
native_response.c
native_session_logger.cc
package-native-response.py
package-session-engine.py
package.py
preview.py
rule-update.conf
snort-home-net.service
snort-home-net.timer
snort.lua
suppress.lua
test_app.js
tests/angular-chart-tooltip.mjs
tests/angular-go-backend.mjs
tests/angular-rule-manager.mjs
tests/check_native_response.py
tests/check_native_session_logger.py
tests/check_ndr_metadata.py
tests/check_nfq_nat.py
tests/check_public_source.py
tests/check_quic_observer.py
tests/check_response_capture.py
tests/check_snort_history_reset.py
tests/check_snort_native.py
tests/run_backend.py
tests/run_browser_regression.py
tests/snort_pcap.py
tests/test-attack-mapping.cjs
tests/test-chart-zoom.cjs
tests/test-connection-summary.cjs
tests/test-console-scroll.cjs
tests/test-data-layer.cjs
tests/test-live-recovery.cjs
tests/test-local-assistant-stream.cjs
tests/test-modal-backdrop.cjs
tests/test-navigation.cjs
tests/test-output.mjs
tests/test-overview-range.cjs
tests/test-range-context.cjs
tests/test-rule-job-logs.cjs
tests/test_build_workflow.py
tests/test_engine_platform.py
tests/test_deploy_backend.py
tests/test_deploy_nft.py
tests/test_go_backend.py
tests/test_go_runtime.py
tests/test_postgresql_deploy.py
tests/test_native_deploy.py
tests/test_native_response_deploy.py
tests/test_public_source.py
tests/test_session_logger_deploy.py
tests/test_snort_config_deploy.py
threshold.config
var-log-ips.mount
var-log-snort.mount'''.split()
EXECUTABLE = {'ips-event-bridge','ips-snort-rules','snort-home-net','ips-web','ips-supervisor','ips-log-maintenance','ips-rule-manager','ips-quic-observer','ips-maintenance','recover-event-db','deploy.sh'}


def build(output,reuse_ui=None):
    from build_frontend import build as build_ui, source_files
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('Export releases outside the source directory')
    checks = subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-p','test_*.py','-q'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if checks.returncode:
        sys.stderr.buffer.write(checks.stdout)
        checks.check_returncode()
    with tempfile.TemporaryDirectory(prefix='aegis-static-') as generated:
        if reuse_ui:
            with tarfile.open(reuse_ui) as prior:
                manifest=json.load(prior.extractfile('snort-ndr/frontend-build.json'))
                for name in (*manifest['files'],'frontend-build.json','frontend-licenses.txt'):
                    if Path(name).name!=name:
                        raise ValueError('Unexpected reusable UI member')
                    (Path(generated)/name).write_bytes(prior.extractfile('snort-ndr/'+name).read())
            expected={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files()}
            if manifest['sources']!=expected:
                raise ValueError('Reusable UI source manifest differs; run a production frontend build')
        else:
            build_ui(Path(generated))
        from build_tools.go_backend import release as build_backend
        build_backend(Path(generated))
        return archive_release(output, Path(generated), source_files())


def archive_release(output, generated, sources):
    frontend = [p.relative_to(ROOT).as_posix() for p in sources]
    chunks = sorted(path.name for path in generated.glob('chunk-*.js'))
    for receipt in ('backend-build.json','maintenance-build.json','supervisor-build.json'):
        if not (generated/receipt).is_file():raise ValueError('Missing native runtime receipt: '+receipt)
    binary_files = []
    native_names=[]
    if (generated/'backend-build.json').is_file():
        manifest=json.loads((generated/'backend-build.json').read_text())
        native_names=[*manifest['files'],'backend-build.json','backend-licenses.txt']
        binary_files.extend(native_names)
        for name,digest in manifest['files'].items():
            if Path(name).name!=name or hashlib.sha256((generated/name).read_bytes()).hexdigest()!=digest:
                raise ValueError('Native backend manifest differs')
    for receipt in ('maintenance-build.json','supervisor-build.json'):
        if (generated/receipt).is_file():
            manifest=json.loads((generated/receipt).read_text())
            binary_files.extend((*manifest['files'],receipt))
            for name,digest in manifest['files'].items():
                if Path(name).name!=name or hashlib.sha256((generated/name).read_bytes()).hexdigest()!=digest:
                    raise ValueError('Native runtime manifest differs')
    backend_sources=[p.relative_to(ROOT).as_posix() for p in (ROOT/'backend').rglob('*') if p.is_file() and p.suffix in ('.go','.json','.sql','.html','.mod','.sum')]
    names=sorted(set(FILES+backend_sources+frontend+chunks+binary_files+['index.html','app.js','ui.js','app.css','frontend-build.json','frontend-licenses.txt']))
    payloads = {}
    generated_names = {'index.html', 'app.js', 'ui.js', 'app.css', 'frontend-build.json', 'frontend-licenses.txt', *chunks, *binary_files}
    for name in names:
        data = ((generated if name in generated_names else ROOT) / name).read_bytes()
        payloads[name] = data if name in frontend or name in binary_files else data.removeprefix(b'\xef\xbb\xbf').replace(b'\r\n', b'\n')
    manifest=json.loads(payloads['frontend-build.json'])
    for name,digest in {**manifest['sources'],**manifest['files']}.items():
        if name not in payloads or hashlib.sha256(payloads[name]).hexdigest()!=digest:
            raise ValueError('Release contains a missing or stale frontend file: '+name)
    sums = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                   for name, data in sorted(payloads.items())).encode()
    release = hashlib.sha256(sums).hexdigest()[:16]
    payloads['RELEASE'] = (release + '\n').encode()
    payloads['SHA256SUMS'] = sums + hashlib.sha256(payloads['RELEASE']).hexdigest().encode() + b'  RELEASE\n'
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(payloads.items()):
            info = tarfile.TarInfo('snort-ndr/' + name)
            info.size, info.mtime = len(data), 0
            info.mode = 0o755 if name in EXECUTABLE else 0o644
            archive.addfile(info, io.BytesIO(data))
    output.mkdir(exist_ok=True)
    target = output / ('snort-ndr-' + release + '.tar.gz')
    target.write_bytes(gzip.compress(stream.getvalue(), mtime=0))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(target.suffix + '.sha256').write_text(digest + '  ' + target.name + '\n', encoding='utf-8')
    print(target)
    print('SHA256 ' + digest)
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reuse-ui-package',type=Path)
    args=parser.parse_args()
    build(args.output,args.reuse_ui_package)
