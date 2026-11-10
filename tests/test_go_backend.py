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
    for name in module.NATIVE_PROGRAMS|module.MAINTENANCE_PROGRAMS:
        (directory/name).write_bytes(data)
        manifest['files'][name]=hashlib.sha256(data).hexdigest()
    base=dict(manifest,files={name:manifest['files'][name] for name in module.NATIVE_PROGRAMS})
    maintenance=dict(manifest,files={name:manifest['files'][name] for name in module.MAINTENANCE_PROGRAMS})
    (directory/'backend-build.json').write_text(json.dumps(base))
    (directory/'maintenance-build.json').write_text(json.dumps(maintenance))
    (directory/'signature-sources.json').write_bytes((ROOT/'signature-sources.json').read_bytes())
    return base


class NativeBackendTests(unittest.TestCase):
    def test_obsolete_components_are_retired_after_health_and_restored_on_failure(self):
        for failure in (False,True):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                module=deployer();root=Path(temporary);release=root/'release';installed=root/'installed'
                release.mkdir();installed.mkdir()
                manifest=native_fixture(release,module)
                for name in ('deployment_support.py','deployment_layout.py'):(release/name).write_text('# deployment helper\n')
                for name in (*module.PROGRAMS,'backend-build.json','maintenance-build.json'):(installed/name).write_bytes((release/name).read_bytes())
                retired=installed/'snort_rules.py';retired.write_bytes(b'# obsolete installation fixture\n')
                cached=installed/'__pycache__/snort_rules.cpython-313.pyc';cached.parent.mkdir();cached.write_bytes(b'obsolete bytecode fixture')
                config=root/'config';config.write_text('{"password_pbkdf2":"fixture"}')
                pid=root/'pid';pid.write_text('123')
                client=mock.Mock();client.request.return_value={'ok':True,'ready':True}
                def health(_):
                    self.assertTrue(retired.exists(),'old components remain until health succeeds')
                    if failure:raise RuntimeError('unhealthy fixture')
                    return dict(sqlite_version='3.54.1',backend='go',go_version='go1.27.3')
                ready=mock.Mock(side_effect=[RuntimeError('unhealthy fixture'),{}]) if failure else health
                with mock.patch.multiple(module,CONFIG=config,BIN=installed,BACKUPS=root/'backups',SIGNATURE_SOURCES=root/'signature-sources.json',PIDFILE=pid,RESOURCE_ROOT=root/'units'),mock.patch.object(module,'validate_go_manifest',return_value=manifest),mock.patch.object(module,'Client',return_value=client),mock.patch.object(module.subprocess,'run'),mock.patch('builtins.print'):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError,'unhealthy fixture'):module.apply(release,ready,{})
                    else:module.apply(release,ready,{})
                self.assertEqual(retired.exists(),failure)
                self.assertEqual(cached.exists(),failure)
                sources=root/'signature-sources.json'
                if failure:self.assertFalse(sources.exists())
                else:self.assertEqual(sources.read_bytes(),(release/sources.name).read_bytes())
                backup=next((root/'backups').iterdir())
                self.assertEqual((backup/retired.name).read_bytes(),b'# obsolete installation fixture\n')
                self.assertEqual((backup/'__pycache__'/cached.name).read_bytes(),b'obsolete bytecode fixture')
                self.assertEqual(json.loads(config.read_text()),{'password_pbkdf2':'fixture'})
                self.assertEqual(pid.read_text(),'123')

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
            manifest=native_fixture(release,module)
            sources=root/'signature-sources.json';sources.write_bytes(b'{"administrator":"fixture"}')
            config=root/'config';original=b'{"password_pbkdf2":"fixture"}\n';config.write_bytes(original)
            pid=root/'pid';pid.write_text('12345')
            client=mock.Mock();client.request.return_value={'ok':True,'ready':True}
            ready=mock.Mock(side_effect=[dict(sqlite_version='3.54.1',backend='python'),dict(ok=True)])
            with mock.patch.multiple(module,CONFIG=config,BIN=installed,BACKUPS=root/'backups',SIGNATURE_SOURCES=root/'signature-sources.json',PIDFILE=pid,RESOURCE_ROOT=root/'units'), \
                 mock.patch.object(module,'validate_native_release',return_value=manifest), \
                 mock.patch.object(module,'validate_go_manifest',return_value=manifest),mock.patch.object(module,'Client',return_value=client),mock.patch.object(module.subprocess,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'native Go backend'):
                    module.apply(release,ready,{},console_only=True,with_rule_manager=True)
            self.assertEqual(config.read_bytes(),original)
            self.assertEqual(sources.read_bytes(),b'{"administrator":"fixture"}')
            for name in module.PROGRAMS:self.assertEqual((installed/name).read_text(),'# previous helper\n')
            self.assertFalse((installed/'backend-build.json').exists())
            self.assertEqual(pid.read_text(),'12345')
            service_calls=[call.args[0][1:] for call in run.call_args_list if call.args[0][1] in ('stop','start')]
            self.assertEqual(service_calls,[
                ['stop','ips-web','ips-rule-manager'], ['start','ips-rule-manager','ips-web'],
                ['stop','ips-web','ips-rule-manager'], ['start','ips-rule-manager','ips-web'],
            ])


if __name__=='__main__':unittest.main()
