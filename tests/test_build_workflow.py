"""Build isolation, verified downloads and deterministic source releases."""
import hashlib
import base64
import importlib.util
import io
import os
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build_frontend
from build_tools import runtime
import package


class BuildWorkflowCase(unittest.TestCase):
    def test_node_policy_rejects_older_lts_and_prerelease_toolchains(self):
        cases = {'v22.22.3':False, 'v24.22.2':False, 'v26.0.0':False,
                 'v'+runtime.NODE_VERSION:True, 'v27.0.0-alpha.0.0.0':False,
                 'v27.0.0':False, 'v26.13.1-beta.1':False}
        for version, expected in cases.items():
            with self.subTest(version=version), mock.patch.object(runtime.subprocess,'check_output',return_value=version):
                self.assertEqual(runtime.compatible(Path('node')),expected)

    def test_unsupported_explicit_node_override_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ,{'NDR_NODE':str(Path(directory)/'old-node')}), \
                mock.patch.object(runtime.subprocess,'check_output',return_value='v22.22.3'), \
                mock.patch.object(runtime,'download') as download:
            with self.assertRaisesRegex(RuntimeError,'same LTS major'):
                runtime.toolchain(Path(directory))
            download.assert_not_called()

    def test_old_or_prerelease_npm_is_replaced_without_global_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);cli=work/'npm/bin/npm-cli.js';cli.parent.mkdir(parents=True)
            metadata=cli.parent.parent/'package.json'
            for version, expected in [('11.20.0',False),(runtime.NPM_VERSION,True),('12.2.2-beta.1',False)]:
                metadata.write_text(json.dumps({'version':version}))
                self.assertEqual(runtime.compatible_npm(cli),expected)
            metadata.write_text(json.dumps({'version':runtime.NPM_VERSION}))
            with mock.patch.object(runtime,'npm_cli',return_value=cli),mock.patch.object(runtime,'download') as download:
                self.assertEqual(runtime.npm_toolchain(work/'node',work),cli)
                download.assert_not_called()

    def test_npm_archive_integrity_is_verified_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);archive=work/'npm.tgz';archive.write_bytes(b'changed tarball')
            source=dict(runtime.TOOLCHAIN['npm'],integrity='sha512-'+base64.b64encode(hashlib.sha512(b'expected').digest()).decode())
            with mock.patch.dict(runtime.TOOLCHAIN,{'npm':source}), \
                    mock.patch.object(runtime,'npm_cli',return_value=None),mock.patch.object(runtime,'download',return_value=archive):
                with self.assertRaisesRegex(RuntimeError,'npm archive checksum mismatch'):
                    runtime.npm_toolchain(work/'node',work)
            self.assertFalse(archive.exists())
            self.assertFalse((work/'npm-toolchain').exists())

    def test_download_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'download'
            with mock.patch.object(runtime.urllib.request, 'urlopen', return_value=io.BytesIO(b'changed')):
                with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                    runtime.download('https://example.invalid/data', target, hashlib.sha256(b'expected').hexdigest())
            self.assertFalse(target.exists())

    def test_dependencies_and_generated_catalog_are_not_source_inputs(self):
        paths = {path.relative_to(ROOT).as_posix() for path in build_frontend.source_files()}
        self.assertIn('frontend/package-lock.json', paths)
        self.assertIn('build_tools/attack-sources.json', paths)
        self.assertIn('build_tools/toolchain-sources.json', paths)
        self.assertNotIn('frontend/src/app/attack-catalog.ts', paths)
        self.assertNotIn('frontend/src/mitre-attack.LICENSE.txt', paths)
        self.assertFalse(any('node_modules' in path or '/dist/' in path for path in paths))

    def test_failed_preparation_removes_temporary_environment(self):
        observed = []
        def fail(frontend, work):
            observed.append(work)
            raise RuntimeError('unavailable input')
        with tempfile.TemporaryDirectory() as output, mock.patch.object(build_frontend, 'generate', side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, 'unavailable input'):
                build_frontend.build(Path(output))
        self.assertTrue(observed)
        self.assertTrue(all(not path.exists() for path in observed))

    def test_release_is_deterministic_and_has_no_runtime_data(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            generated = work / 'static'
            generated.mkdir()
            for name in ('index.html', 'app.js', 'ui.js', 'app.css', 'frontend-build.json', 'frontend-licenses.txt', 'python-dependencies.zip'):
                (generated / name).write_text(name, encoding='utf-8')
            (generated / 'chunk-ABC123.js').write_text('export const chart = true;', encoding='utf-8')
            assets=('index.html','app.js','ui.js','app.css','chunk-ABC123.js')
            (generated/'frontend-build.json').write_text(json.dumps(dict(sources={},files={name:hashlib.sha256((generated/name).read_bytes()).hexdigest() for name in assets})))
            with mock.patch('sys.stdout', new=io.StringIO()):
                first = package.archive_release(work / 'first', generated, build_frontend.source_files())
                second = package.archive_release(work / 'second', generated, build_frontend.source_files())
            self.assertEqual(first.name, second.name)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                names = archive.getnames()
            self.assertIn('snort-ndr/build_tools/attack-sources.json', names)
            self.assertIn('snort-ndr/AGENTS.md', names)
            self.assertIn('snort-ndr/ips-web.service', names)
            self.assertIn('snort-ndr/deploy-snort3.py', names)
            self.assertIn('snort-ndr/snort_engine.py', names)
            self.assertIn('snort-ndr/tests/test_native_deploy.py', names)
            self.assertIn('snort-ndr/chunk-ABC123.js', names)
            for name in assets:self.assertIn('snort-ndr/'+name,names)
            self.assertNotIn('snort-ndr/nftables.conf', names)
            self.assertFalse(any('/node_modules/' in name or '/artifacts/' in name or '/backup/' in name or name.endswith('.db') for name in names))

    def test_tool_environment_keeps_cache_and_node_in_work_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            env = runtime.environment(work / 'node/node.exe', work)
            self.assertEqual(env['npm_config_cache'], str(work / 'npm-cache'))
            self.assertTrue(env['PATH'].startswith(str(work / 'node') + os.pathsep))
            self.assertEqual(len([key for key in env if key.upper() == 'PATH']), 1)


if __name__ == '__main__':
    unittest.main()
