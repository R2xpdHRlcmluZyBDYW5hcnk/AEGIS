"""Native executable integrity, deterministic release metadata and rollback."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def deployer():
    spec=importlib.util.spec_from_file_location('go_deployer',ROOT/'deploy-native-backend.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def native_fixture(directory,module):
    data=bytearray(64);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',data,18,183)
    manifest=dict(schema=1,backend='go',target='linux-arm64',go_version='1.27.3',sqlite_version='3.54.1',files={})
    for name in module.NATIVE_PROGRAMS:
        (directory/name).write_bytes(data)
        manifest['files'][name]=hashlib.sha256(data).hexdigest()
    (directory/'backend-build.json').write_text(json.dumps(manifest))
    return manifest


class NativeBackendTests(unittest.TestCase):
    def test_native_manifest_rejects_missing_tampered_and_wrong_architecture(self):
        module=deployer()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);manifest=native_fixture(root,module)
            self.assertEqual(module.validate_native_release(root,execute=False),manifest)
            (root/'ips-web').write_bytes(b'#!/bin/sh\nexit 0\n')
            with self.assertRaises(ValueError):module.validate_native_release(root,execute=False)
            native_fixture(root,module)
            data=bytearray((root/'ips-web').read_bytes());struct.pack_into('<H',data,18,62)
            (root/'ips-web').write_bytes(data)
            with self.assertRaises(ValueError):module.validate_native_release(root,execute=False)

    def test_failed_go_health_restores_old_programs_and_removes_new_manifest(self):
        module=deployer()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);release=root/'release';installed=root/'installed';release.mkdir();installed.mkdir()
            for name in module.PROGRAMS:
                (release/name).write_text('# candidate helper\n');(installed/name).write_text('# previous helper\n')
            with zipfile.ZipFile(release/'python-dependencies.zip','w') as archive:archive.writestr('luqum/parser.py','# fixture')
            manifest=native_fixture(release,module)
            config=root/'config';original=b'{"password_pbkdf2":"fixture"}\n';config.write_bytes(original)
            pid=root/'pid';pid.write_text('12345')
            client=mock.Mock();client.request.return_value={'ok':True,'ready':True}
            ready=mock.Mock(side_effect=[dict(sqlite_version='3.54.1',backend='python'),dict(ok=True)])
            with mock.patch.multiple(module,CONFIG=config,BIN=installed,BACKUPS=root/'backups',PIDFILE=pid,RESOURCE_ROOT=root/'units'), \
                 mock.patch.object(module,'validate_native_release',return_value=manifest), \
                 mock.patch.object(module,'Client',return_value=client),mock.patch.object(module.subprocess,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'native Go backend'):module.apply(release,ready,{})
            self.assertEqual(config.read_bytes(),original)
            for name in module.PROGRAMS:self.assertEqual((installed/name).read_text(),'# previous helper\n')
            self.assertFalse((installed/'backend-build.json').exists())
            self.assertEqual(pid.read_text(),'12345')
            for call in run.call_args_list:
                if call.args[0][1] in ('stop','start'):
                    self.assertLessEqual(set(call.args[0][2:]),set(module.SERVICES))


if __name__=='__main__':unittest.main()
