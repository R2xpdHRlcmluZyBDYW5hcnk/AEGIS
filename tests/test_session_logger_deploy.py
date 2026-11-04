"""Hot activation validates ABI first and restores protected startup state."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import session_logger as runtime

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('session_deployer',ROOT/'deploy-session-logger.py')
deploy=importlib.util.module_from_spec(spec);spec.loader.exec_module(deploy)


class DeployTests(unittest.TestCase):
    def test_receipt_cannot_supply_a_path_or_command_and_checksum_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);receipt=root/'receipt.json';digest=hashlib.sha256(b'library').hexdigest()
            for value in ('$(id)','../library','x'*64):
                receipt.write_text(json.dumps(dict(sha256=value)))
                with self.assertRaises(ValueError):runtime.plugin_arguments(receipt)
            library=root/digest/'ndr_session.so';library.parent.mkdir();library.write_bytes(b'library')
            receipt.write_text(json.dumps(dict(sha256=digest,path='; command ignored')))
            with mock.patch.object(runtime,'LIBRARY_ROOT',root):
                self.assertEqual(runtime.plugin_arguments(receipt),['--plugin-path',str(library)])
                library.write_bytes(b'tampered')
                with self.assertRaises(ValueError):runtime.plugin_arguments(receipt)

    def test_failed_hot_load_restores_config_receipt_supervisor_and_rotation_without_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);release=root/'release';plugin=root/'plugin';program=root/'program'
            for path in (release,plugin,program):path.mkdir()
            binary=root/'snort';binary.write_bytes(b'engine');config=root/'config.lua';config.write_bytes(b'old config\n')
            rotation=root/'rotation';rotation.write_bytes(b'/var/log/snort/*alert_json.txt {}\n')
            (program/'ips-supervisor').write_bytes(b'old supervisor')
            for name in ('session_logger.py','runtime_status.py','ips-supervisor'):
                (release/name).write_bytes(b'new program')
                if name!='ips-supervisor':(program/name).write_bytes(b'new program')
            (release/'native_session_logger.cc').write_bytes(b'logger source')
            (plugin/'ndr_session.so').write_bytes(b'library')
            digest=hashlib.sha256(b'library').hexdigest()
            (plugin/'session-logger.json').write_text(json.dumps(dict(version=1,session_patch='ndr-session-1',sha256=digest,
                source_sha256=hashlib.sha256(b'logger source').hexdigest(),engine_sha256=hashlib.sha256(b'engine').hexdigest())))
            client=mock.Mock();client.request.return_value={'ok':True};control=mock.Mock()
            control.command.side_effect=['old generation','reload accepted','new generation']
            with mock.patch.multiple(deploy,CONFIG=config,PROGRAM=program,BINARY=str(binary),BACKUPS=root/'backups',ROTATION=rotation), \
                    mock.patch.multiple(runtime,RECEIPT=root/'receipt.json',LIBRARY_ROOT=root/'libraries',MARKER=root/'marker'), \
                    mock.patch.object(deploy,'Client',return_value=client),mock.patch.object(deploy,'SnortControl',return_value=control), \
                    mock.patch.object(runtime,'process_key',return_value=[1,'2','3']), \
                    mock.patch.object(deploy.subprocess,'run',return_value=mock.Mock(returncode=0)) as run, \
                    mock.patch.object(runtime,'reload_extension',side_effect=RuntimeError('synthetic hot load failure')):
                with self.assertRaisesRegex(RuntimeError,'synthetic'):deploy.deploy(release,plugin)
            self.assertEqual(config.read_bytes(),b'old config\n')
            self.assertEqual((program/'ips-supervisor').read_bytes(),b'old supervisor')
            self.assertEqual(rotation.read_bytes(),b'/var/log/snort/*alert_json.txt {}\n')
            self.assertFalse((root/'receipt.json').exists())
            self.assertEqual(binary.read_bytes(),b'engine')
            self.assertEqual(run.call_count,1);self.assertIn('-T',run.call_args.args[0])
            self.assertEqual(client.request.call_args,mock.call('maintenance',enabled=False))


if __name__=='__main__':unittest.main()
