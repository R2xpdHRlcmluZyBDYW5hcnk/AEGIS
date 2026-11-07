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
FILES = '''tests/test-live-recovery.cjs tests/test-local-assistant-stream.cjs tests/test_ai_evidence.py tests/check_llm_rules.py tests/test_overview_cohorts.py dns_context.py llm_hunting.py overview_metrics.py hunt_query.py python_dependencies.py openappid_update.py session_logger.py native_session_logger.cc deploy-session-logger.py build_tools/build_session_logger.py build_tools/snort-sources.json build_tools/patch_snort.py build_tools/python-sources.json build_tools/python_dependencies.py tests/run_backend.py tests/run_hunt_regression.py tests/test_hunt_language.py tests/test_openappid_update.py tests/test_session_logger.py tests/test_session_logger_deploy.py tests/check_native_session_logger.py
ips-web ips-supervisor ips-log-maintenance ips-rule-manager ips-event-bridge ips-snort-rules snort-home-net
ips_control.py rule_drafts.py llm_assistant.py quic_observer.py snort_engine.py snort_rules.py rule_policy.py parallel_cpu.py parallel_sql.py event_processing.py native_rules.py rule_sources.py rule_identity.py rule_inventory.py runtime_status.py history_reset.py log_storage.py deployment_layout.py
ips-quic-observer.service deploy-quic-observer.py build_tools/quic-sources.json docs/quic-observer.md tests/test_quic_observer.py tests/check_quic_observer.py tests/check_snort_sessions.py tests/check_nfq_nat.py docs/event-search.md
ips.service ips-web.service ips-rule-manager.service ips-event-bridge.service ips-web-isolated.conf ips-web.conf
snort-home-net.service snort-home-net.timer ips-log-maintenance.service ips-log-maintenance.timer ips-restore.conf
snort.lua home-net.lua suppress.lua rule-update.conf ips-web-bans.lua local.rules ips-web-hunting.rules threshold.config drop.conf disable.conf modify.conf action-override.conf logrotate-snort
favicon.svg deploy.sh deploy.ps1 deploy-angular.py deploy-backend.py deploy-native-backend.py deploy-snort3.py deploy-session-engine.py deploy-log-storage.py cleanup-legacy-suricata.py cleanup-native-logs.py var-log-snort.mount var-log-ips.mount package-session-engine.py deploy-nft.py deploy-supervisor.py native_response.c package-native-response.py deploy-native-response.py tests/check_native_response.py tests/test_native_response_deploy.py
package.py build_frontend.py preview.py recover-event-db.py cleanup-workspace.ps1 AGENTS.md README.md README-deploy.md IPS-使用说明.md LICENSE THIRD_PARTY_NOTICES.md LICENSES/GPL-2.0.txt LICENSES/Snort-COPYING.txt docs/license-sources.md
docs/snort3-engine.md docs/rule-source-verification.md docs/local-llm.md docs/log-storage.md docs/dependency-policy.md docs/hunt-state-values.md docs/sqlite-recovery.md docs/nfqueue-rules.md docs/history-management.md docs/native-response.md docs/rule-management.md docs/parallel-processing.md
build_tools/build-snort3-arm64.sh tests/snort_pcap.py tests/test_snort_engine.py tests/test_native_deploy.py tests/check_snort_native.py tests/check_rule_catalog.py tests/check_rule_policy.py tests/test_rule_policy.py tests/check_response_capture.py tests/check_overview_events.py tests/angular-overview-filters.mjs tests/run_chart_regression.py tests/test_parallel_runtime.py tests/check_multicore.py
 test_ips_web.py test_app.js tests/test_llm_assistant.py tests/test_llm_context.py tests/angular-local-llm.mjs tests/test_rule_manager.py tests/test_rule_manager_transport.py tests/test_bridge_recovery.py tests/test_legacy_cleanup.py tests/test_native_log_cleanup.py tests/test_log_storage.py tests/test_log_storage_paths.py tests/check_log_storage.py tests/test_native_rule_management.py tests/test_group_policies.py tests/test_rule_inventory.py tests/test_telemetry.py tests/test_runtime_status.py tests/test_history_reset.py tests/test_session_identity.py tests/check_native_rule_management.py tests/test_rule_selection.py tests/test_nft_rules.py tests/test_deploy_nft.py tests/test_supervisor.py tests/test_event_db_recovery.py
 tests/test-navigation.cjs tests/angular-navigation.mjs tests/angular-suppression-groups.mjs tests/angular-rule-manager.mjs tests/angular-native-rules.mjs tests/angular-group-policy.mjs tests/angular-runtime-status.mjs tests/angular-source-filter.mjs tests/angular-rule-styling.mjs tests/angular-history-reset.mjs tests/angular-pagination.mjs tests/angular-rule-performance.mjs tests/serve_preview.py tests/browser-smoke.mjs tests/test_build_workflow.py tests/check_public_source.py'''.split()
EXECUTABLE = {'ips-event-bridge','ips-snort-rules','snort-home-net','ips-web', 'ips-supervisor', 'ips-log-maintenance', 'ips-rule-manager','deploy.sh'}
FILES.append('tests/test-rule-job-logs.cjs')
FILES.append('tests/test_ingest_resume.py')
FILES.extend(('tests/check_ndr_metadata.py','tests/benchmark_network_summary.py','docs/ndr-observability.md'))
FILES.extend(('deploy-snort-config.py','tests/test_snort_config_deploy.py'))


def build(output,reuse_ui=None,with_sqlite_runtime=False):
    from build_tools.python_dependencies import environment
    if not os.environ.get('NDR_PYTHON_DEPS'):
        with environment():return _build(output,reuse_ui,with_sqlite_runtime)
    return _build(output,reuse_ui,with_sqlite_runtime)


def _build(output,reuse_ui=None,with_sqlite_runtime=False):
    from build_frontend import build as build_ui, source_files
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('Export releases outside the source directory')
    checks = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-q',
                             'tests.test_snort_engine', 'tests.test_rule_policy', 'tests.test_parallel_runtime', 'tests.test_ingest_resume', 'tests.test_native_deploy', 'tests.test_deploy_backend', 'tests.test_event_db_recovery', 'tests.test_snort_config_deploy',
                             'tests.test_quic_observer', 'tests.test_llm_assistant', 'tests.test_llm_context', 'tests.test_rule_manager', 'tests.test_rule_manager_transport', 'tests.test_bridge_recovery', 'tests.test_legacy_cleanup', 'tests.test_native_log_cleanup', 'tests.test_log_storage', 'tests.test_log_storage_paths', 'tests.test_native_rule_management', 'tests.test_group_policies', 'tests.test_rule_inventory', 'tests.test_telemetry', 'tests.test_runtime_status', 'tests.test_history_reset', 'tests.test_session_identity', 'tests.test_rule_selection',
                             'tests.test_nft_rules', 'tests.test_deploy_nft', 'tests.test_supervisor', 'tests.test_native_response_deploy', 'tests.test_hunt_language', 'tests.test_openappid_update', 'tests.test_session_logger', 'tests.test_session_logger_deploy','tests.test_overview_cohorts','tests.test_ai_evidence'], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
        if with_sqlite_runtime:
            from build_tools.build_sqlite_runtime import build as build_sqlite
            build_sqlite(Path(generated))
        shutil.copy2(os.environ['NDR_PYTHON_DEPS'],Path(generated)/'python-dependencies.zip')
        return archive_release(output, Path(generated), source_files())


def archive_release(output, generated, sources):
    frontend = [p.relative_to(ROOT).as_posix() for p in sources]
    chunks = sorted(path.name for path in generated.glob('chunk-*.js'))
    binary_files = ['python-dependencies.zip']
    if (generated/'libsqlite3-ndr.so').is_file():
        binary_files.append('libsqlite3-ndr.so')
    names = sorted(set(FILES + frontend + chunks + binary_files + ['index.html','app.js','ui.js','app.css','build_frontend.py', 'frontend-build.json', 'tests/test-data-layer.cjs', 'tests/test-connection-summary.cjs', 'tests/check_data_layer.py',
                       'deploy-angular.py', 'deploy-backend.py', 'tests/angular-smoke.mjs', 'tests/angular-pointer.mjs', 'tests/angular-ux.mjs', 'tests/angular-hunt-suggestions.mjs', 'tests/angular-system-capacity.mjs', 'tests/angular-reset.mjs', 'tests/angular-chart-tooltip.mjs', 'tests/test_hunt_suggestions.py', 'tests/test_mitre_attack.py', 'tests/test-attack-mapping.cjs', 'tests/test-console-scroll.cjs', 'frontend-licenses.txt'] +
                       ['tests/test-output.mjs', 'tests/test-overview-range.cjs', 'tests/test-modal-backdrop.cjs', 'tests/test-range-context.cjs', 'tests/test-chart-zoom.cjs', 'tests/test_network_visibility.py', 'tests/test_network_snapshots.py', 'tests/test_static_modules.py', 'tests/test_deploy_backend.py', 'tests/audit_hunt_queries.py', 'tests/test_hunt_query_matrix.py', 'tests/test_data_layer.py']))
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
    parser.add_argument('--with-sqlite-runtime',action='store_true')
    args=parser.parse_args()
    build(args.output,args.reuse_ui_package,args.with_sqlite_runtime)
