"""Console-only deployment must never target the detector or leave partial files."""
import importlib.util
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backend_deployer', ROOT / 'deploy-backend.py')
deployer = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {'fcntl': types.SimpleNamespace()} if sys.platform == 'win32' else {}):
    spec.loader.exec_module(deployer)


class BackendDeploymentCase(unittest.TestCase):
    def test_resource_validation_and_whitelist(self):
        self.assertEqual(deployer.resource_overrides({'read_workers':4,'password_pbkdf2':'ignored'}),{'read_workers':4})
        self.assertEqual(deployer.resource_overrides({'llm_summary_max_tokens':1024}),{'llm_summary_max_tokens':1024})
        self.assertEqual(deployer.resource_overrides({'preload_memory_mib':512}),{'preload_memory_mib':512})
        for values in ({'read_workers':0},{'stats_batch_size':100000},{'cache_memory_percent':float('nan')},{'llm_summary_max_tokens':4096},{'preload_memory_mib':1025}):
            with self.assertRaises(ValueError):
                deployer.resource_overrides(values)

    def resource_upgrade(self,fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target,config,release = root/'installed',root/'config.json',root/'release'
            release.mkdir()
            target.write_bytes(b'same backend');(release/'ips-web').write_bytes(target.read_bytes())
            original = b'{"password_pbkdf2":"fixture-secret","port":9000,"read_workers":1}\n'
            config.write_bytes(original)
            def digest(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()
            def snapshot(cfg):
                return dict(files={str(target):digest(target),str(config):digest(config)},
                            db_inode=1,db_sample=[1],db_rows=20,engine_pid=10,supervisor_pid=11,crontab='same')
            helper = types.SimpleNamespace(digest=digest,snapshot=snapshot)
            with mock.patch.object(deployer,'TARGET',target),mock.patch.object(deployer,'CONFIG',config), \
                 mock.patch.object(deployer,'BACKUP_ROOT',root/'backups'), \
                 mock.patch.object(deployer,'restart_console') as restart, \
                 mock.patch.object(deployer,'wait_ready',side_effect=[RuntimeError('startup failure'),None] if fail else None), \
                 mock.patch('sys.stdout',new=io.StringIO()):
                if fail:
                    with self.assertRaisesRegex(RuntimeError,'startup failure'):
                        deployer.upgrade(release,helper,{'read_workers':3})
                    self.assertEqual(config.read_bytes(),original)
                    self.assertEqual(target.read_bytes(),b'same backend')
                    self.assertEqual(restart.call_count,2)
                else:
                    deployer.upgrade(release,helper,{'read_workers':3})
                    self.assertEqual(json.loads(config.read_bytes()),dict(password_pbkdf2='fixture-secret',port=9000,read_workers=3))
                    restart.assert_called_once_with(11)

    def test_resource_only_upgrade_preserves_authentication(self):
        self.resource_upgrade()

    def test_resource_failure_restores_original_configuration_and_backend(self):
        self.resource_upgrade(fail=True)

    def test_atomic_install_and_failed_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            target, source = Path(directory) / 'installed', Path(directory) / 'candidate'
            target.write_bytes(b'old')
            source.write_bytes(b'new')
            with mock.patch.object(deployer, 'TARGET', target):
                with mock.patch.object(deployer.os, 'replace', side_effect=OSError('fixture failure')):
                    with self.assertRaises(OSError):
                        deployer.install(source)
                self.assertEqual(target.read_bytes(), b'old')
                self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['candidate', 'installed'])
                deployer.install(source)
                self.assertEqual(target.read_bytes(), b'new')

    def test_restart_only_targets_console_children_of_the_supervisor(self):
        def process(pid, parent, args):
            proc = mock.Mock()
            proc.name = str(pid)
            def child(name):
                value = mock.Mock()
                value.read_text.return_value = 'PPid:\t' + str(parent)
                value.read_bytes.return_value = b'\0'.join(args)
                return value
            proc.__truediv__ = mock.Mock(side_effect=child)
            proc.exists.return_value = False
            return proc
        procs = [process(10, 1, [b'python3', b'/usr/local/bin/ips-web']),
                 process(11, 100, [b'/opt/ips-snort3/3.12.4.0/bin/snort']),
                 process(12, 100, [b'python3', b'/usr/local/bin/ips-web'])]
        with mock.patch.object(deployer, 'Path') as path, mock.patch.object(deployer.os, 'kill') as kill, \
                mock.patch.object(deployer, 'TARGET', PurePosixPath('/usr/local/bin/ips-web')), \
                mock.patch.object(deployer, 'independent_console', return_value=False):
            path.return_value.iterdir.return_value = procs
            deployer.restart_console('100')
        kill.assert_called_once_with(12, deployer.signal.SIGTERM)

    def test_independent_console_restart_does_not_signal_the_detector(self):
        with mock.patch.object(deployer, 'independent_console', return_value=True), \
                mock.patch.object(deployer.subprocess, 'run') as run, \
                mock.patch.object(deployer.os, 'kill') as kill:
            deployer.restart_console('100')
        run.assert_called_once_with(['systemctl', 'restart', 'ips-web.service'], check=True)
        kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
