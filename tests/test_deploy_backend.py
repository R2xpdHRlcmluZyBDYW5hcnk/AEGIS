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
    def test_console_only_reuses_configured_postgresql(self):
        isolation = mock.Mock()
        helper = mock.Mock()
        config = mock.Mock()
        config.read_bytes.return_value = b'{"database_url":"postgresql:///aegis"}'
        with (mock.patch.object(deployer.Path, 'is_file', return_value=True),
              mock.patch.object(deployer, 'CONFIG', config),
              mock.patch.object(deployer.importlib.util, 'spec_from_file_location') as spec,
              mock.patch.object(deployer.importlib.util, 'module_from_spec', return_value=isolation)):
            release = ROOT
            deployer.upgrade(release, helper, {}, console_only=True)
        spec.assert_called_once_with('web_isolation', release / 'deploy-native-backend.py')
        isolation.apply.assert_called_once_with(
            release, deployer.wait_ready, {}, helper.snapshot, reset_event_data=False, console_only=True)

    def test_resource_validation_and_whitelist(self):
        self.assertEqual(deployer.resource_overrides({'cache_max_mib':128,'read_workers':4,'password_pbkdf2':'ignored'}),{'cache_max_mib':128})
        self.assertEqual(deployer.resource_overrides({'llm_summary_max_tokens':1024}),{'llm_summary_max_tokens':1024})
        self.assertEqual(deployer.resource_overrides({'preload_memory_mib':512}),{'preload_memory_mib':512})
        for values in ({'stats_batch_size':100000},{'cache_memory_percent':float('nan')},{'llm_summary_max_tokens':4096},{'preload_memory_mib':1025}):
            with self.assertRaises(ValueError):
                deployer.resource_overrides(values)








if __name__ == '__main__':
    unittest.main()
