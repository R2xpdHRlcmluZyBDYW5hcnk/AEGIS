"""Build and validate Angular in a temporary dependency environment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from build_tools.attack_catalog import generate
from build_tools.runtime import environment, toolchain

ROOT = Path(__file__).resolve().parent
GENERATED = {'attack-catalog.ts', 'mitre-attack.LICENSE.txt'}


def source_files():
    frontend = ROOT / 'frontend'
    names = ('package.json', 'package-lock.json', 'angular.json', 'tsconfig.json',
             'proxy.conf.json', '.gitignore', 'README.md')
    return sorted([frontend / name for name in names if (frontend / name).is_file()] +
                  [p for p in (frontend / 'src').rglob('*')
                   if p.is_file() and p.name not in GENERATED and p.suffix in ('.ts', '.css', '.html')] +
                  [p for p in (ROOT / 'build_tools').iterdir() if p.suffix in ('.py', '.json')])


def run(command, cwd, env):
    result = subprocess.run([str(part) for part in command], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        sys.stderr.buffer.write(result.stdout)
        result.check_returncode()
    return result


def build(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='aegis-build-') as directory:
        work = Path(directory)
        project = work / 'project'
        project.mkdir()
        sources = source_files()
        for path in sources:
            target = project / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        frontend = project / 'frontend'
        print('Preparing pinned MITRE reference data', file=sys.stderr, flush=True)
        generate(frontend, work)
        node, npm = toolchain(work)
        env = environment(node, work)
        print('Installing locked npm dependencies in a temporary directory', file=sys.stderr, flush=True)
        run([node, npm, 'ci', '--no-audit', '--no-fund'], frontend, env)
        print('Building Angular and checking release integrity', file=sys.stderr, flush=True)
        run([node, frontend / 'node_modules/@angular/cli/bin/ng.js', 'build'], frontend, env)
        browser = frontend / 'dist/console/browser'
        mapping = {'app.js': 'main.js', 'ui.js': 'polyfills.js', 'app.css': 'styles.css'}
        payloads = {name: (browser / original).read_bytes() for name, original in mapping.items()}
        for chunk in browser.glob('chunk-*.js'):
            payloads[chunk.name] = chunk.read_bytes()
        index = (browser / 'index.html').read_text(encoding='utf-8')
        for name, original in mapping.items():
            version = hashlib.sha256(payloads[name]).hexdigest()[:16]
            index = index.replace('"' + original + '"', '"/' + name + '?v=' + version + '"')
        payloads['index.html'] = index.encode('utf-8')
        for name, data in payloads.items():
            (project / name).write_bytes(data)
        licenses = (frontend / 'dist/console/3rdpartylicenses.txt').read_bytes()
        licenses += b'\n\nMITRE ATT&CK\n' + (frontend / 'src/mitre-attack.LICENSE.txt').read_bytes()
        (project / 'frontend-licenses.txt').write_bytes(licenses)
        manifest = {'framework': 'Angular 22.2.4', 'sources': {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
            'files': {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}}
        (project / 'frontend-build.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        shutil.copy2(ROOT / 'test_app.js', project / 'test_app.js')
        run([node, 'test_app.js'], project, env)
        (project / 'tests').mkdir()
        for name in ('test-attack-mapping.cjs', 'test-console-scroll.cjs', 'test-overview-range.cjs', 'test-modal-backdrop.cjs', 'test-range-context.cjs', 'test-chart-zoom.cjs', 'test-navigation.cjs', 'test-data-layer.cjs', 'test-connection-summary.cjs'):
            shutil.copy2(ROOT / 'tests' / name, project / 'tests' / name)
            run([node, project / 'tests' / name], project, env)
        for name in ('ips-web','snort_engine.py','snort_rules.py','rule_policy.py','parallel_cpu.py','parallel_sql.py','event_processing.py','native_rules.py','rule_sources.py','rule_identity.py','rule_inventory.py','runtime_status.py','history_reset.py','log_storage.py'):
            shutil.copy2(ROOT / name, project / name)
        for name in ('test_static_modules.py', 'test_hunt_suggestions.py', 'test_mitre_attack.py', 'test_network_visibility.py', 'test_network_snapshots.py', 'test_hunt_query_matrix.py', 'test_data_layer.py'):
            if name == 'test_hunt_query_matrix.py' and os.environ.get('NDR_SKIP_QUERY_MATRIX') == '1':
                continue
            shutil.copy2(ROOT / 'tests' / name, project / 'tests' / name)
            run([sys.executable, '-B', project / 'tests' / name], project, env)
        for name in (*payloads, 'frontend-licenses.txt', 'frontend-build.json'):
            shutil.copy2(project / name, output / name)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Explicit destination for generated static files')
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT):
        parser.error('Use an output directory outside the source tree')
    build(args.output)
    print(args.output.resolve())
