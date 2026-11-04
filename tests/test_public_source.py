"""Publication checks report categories without echoing sensitive matches."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('public_source_check', Path(__file__).with_name('check_public_source.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class PublicSourceTests(unittest.TestCase):
    def test_private_host_is_rejected_but_standard_network_template_is_allowed(self):
        network = check.PRIVATE_NETWORKS[-1]
        host = str(network.network_address + 1)
        self.assertTrue(list(check.findings('deploy.ps1', host.encode())))
        self.assertEqual(list(check.findings('home-net.lua', str(network).encode())), [])
        self.assertEqual(list(check.findings('example.txt', b'192.0.2.1')), [])

    def test_personal_paths_and_credentials_are_not_echoed(self):
        path = '/home/' + 'fixture' + '/private'
        secret = 'ghp_' + 'x' * 40
        result = list(check.findings('config.txt', (path + '\n' + secret).encode()))
        self.assertIn('personal path', result)
        self.assertIn('access token', result)
        self.assertFalse(any(secret in item or path in item for item in result))

    def test_authentication_template_and_binary_artifacts_are_rejected(self):
        config = json.dumps(dict(password_pbkdf2='fixture-authentication-material')).encode()
        self.assertIn('production authentication material in template', list(check.findings('ips-web.conf', config)))
        self.assertTrue(list(check.findings('runtime.db', b'SQLite\0')))


if __name__ == '__main__':
    unittest.main()
