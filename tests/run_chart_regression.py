"""Run desktop chart regressions with isolated assets, runtime and synthetic data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from build_tools.runtime import environment, toolchain


def main():
    from build_tools.python_dependencies import environment as dependencies
    with dependencies():return run_checks()


def run_checks():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--release', type=Path)
    source.add_argument('--baseline-host', help='Read only the deployed static assets via SSH')
    parser.add_argument('--with-rules', action='store_true', help='Also check rule operations and request cancellation')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ips-chart-regression-') as directory:
        work = Path(directory)
        static = work/'static'
        static.mkdir()
        if args.baseline_host:
            if args.baseline_host.startswith('-') or any(c.isspace() for c in args.baseline_host):
                parser.error('Invalid SSH target')
            def read(name):
                if not re.fullmatch(r'[A-Za-z0-9._-]+', name):
                    raise ValueError('Unexpected static asset name')
                return subprocess.check_output(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',
                    args.baseline_host, 'cat /usr/local/share/ips-snort-web/'+name])
            manifest = json.loads(read('frontend-build.json'))
            for name, digest in manifest['files'].items():
                data = read(name)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('Static asset changed while copying: '+name)
                (static/name).write_bytes(data)
        else:
            with tarfile.open(args.release) as archive:
                manifest = json.load(archive.extractfile('snort-ndr/frontend-build.json'))
                for name, digest in manifest['files'].items():
                    if Path(name).name != name:
                        raise ValueError('Unexpected static asset name')
                    data = archive.extractfile('snort-ndr/'+name).read()
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise ValueError('Static asset checksum mismatch: '+name)
                    (static/name).write_bytes(data)
        (static/'frontend-build.json').write_text(json.dumps(manifest))
        shutil.copy2(ROOT/'favicon.svg', static/'favicon.svg')
        node, _ = toolchain(work)
        env = environment(node, work)
        stop = work/'preview.stop'
        env.update(NDR_PREVIEW_STATIC_DIR=str(static), NDR_PREVIEW_PORT='19094',
                   NDR_PREVIEW_URL='http://127.0.0.1:19094', NDR_PREVIEW_STOP_FILE=str(stop),
                   NDR_PREVIEW_REJECT_ONLY='1', NDR_TEST_OUTPUT=str(work/'screenshots'))
        if not args.baseline_host:env['NDR_PREVIEW_OVERVIEW']='1'
        if args.baseline_host:
            env['NDR_TOOLTIP_BASELINE'] = '1'
        else:
            env.pop('NDR_TOOLTIP_BASELINE', None)
        log = work/'preview.log'
        with log.open('w') as output:
            preview = subprocess.Popen([sys.executable,'-B',str(ROOT/'tests/serve_preview.py')],
                cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if preview.poll() is not None:
                        raise RuntimeError(log.read_text()[-4000:])
                    try:
                        with urllib.request.urlopen(env['NDR_PREVIEW_URL']+'/login', timeout=.5) as reply:
                            if reply.status == 200:
                                break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError('Chart preview did not start')
                names = ['angular-chart-tooltip.mjs']
                if not args.baseline_host:
                    names.append('angular-overview-filters.mjs')
                if args.with_rules:
                    names.extend(['angular-rule-manager.mjs','angular-rule-performance.mjs'])
                for name in names:
                    print('RUN '+name, flush=True)
                    subprocess.run([str(node),str(ROOT/'tests'/name)], cwd=ROOT, env=env,
                                   check=True, timeout=180)
            finally:
                stop.write_text('stop')
                try:
                    preview.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    preview.kill()
                    preview.wait()


if __name__ == '__main__':
    main()
