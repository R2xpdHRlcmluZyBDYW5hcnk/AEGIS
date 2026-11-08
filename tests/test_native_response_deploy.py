"""The response adapter never replaces Snort or discards native evidence."""
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('response_deployer',ROOT/'deploy-native-response.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class NativeResponseDeployCase(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
        self.release=self.root/'release';self.release.mkdir()
        elf=bytearray(64);elf[:6]=b'\x7fELF\x02\x01';elf[18:20]=(183).to_bytes(2,'little')
        for name,value in {'libips-response.so':elf,'native_response.c':b'source','deploy-native-response.py':b'deployer','deployment_support.py':b'helper'}.items():(self.release/name).write_bytes(value)
        self.manifest=dict(revision=1,architecture='aarch64',sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.release.iterdir()})
        (self.release/'manifest.json').write_text(json.dumps(self.manifest))
        self.logs=self.root/'logs';self.logs.mkdir();self.raw=self.logs/'0_file_connector_ndr_transmit';self.raw.write_text('native evidence\n')
        self.config=self.root/'config.json';self.database=self.root/'events.db';self.database.write_text('database')
        self.config.write_text(json.dumps({'event_db':str(self.database)}))
        self.engine=self.root/'snort';self.engine.write_text('precompiled engine')
        self.instance=self.root/'instance.json';self.instance.write_text('{"epoch":"fixture","started":0}')
        self.library=self.root/'installed/lib.so';self.override=self.root/'unit/response.conf'
        patch=mock.patch.multiple(m,PROGRAM=self.root,LIBRARY=self.library,OVERRIDE=self.override,
            BACKUPS=self.root/'backups',LOGS=self.logs,CHECKPOINT=self.root/'offsets.json',INSTANCE=self.instance,CONFIG=self.config,
            ENGINE=self.engine,PROTECTED=(self.engine,self.config))
        patch.start();self.addCleanup(patch.stop)

    def test_package_validation_rejects_tampering_and_extra_paths(self):
        self.assertEqual(m.verified(self.release)['revision'],1)
        (self.release/'native_response.c').write_text('tampered')
        with self.assertRaises(ValueError):m.verified(self.release)

    def test_archiving_is_same_filesystem_rename_and_preserves_unrelated_files(self):
        other=self.logs/'process.log';other.write_text('operational log')
        inode=self.raw.stat().st_ino
        destination=m.archive_logs('20261104T010000-123')
        self.assertEqual((destination/self.raw.name).read_text(),'native evidence\n')
        self.assertEqual((destination/self.raw.name).stat().st_ino,inode)
        self.assertEqual(other.read_text(),'operational log')

    def test_checkpoint_drain_checks_every_native_writer(self):
        m.CHECKPOINT.write_text(json.dumps({'epoch':'fixture','files':{self.raw.name:{'inode':self.raw.stat().st_ino,'offset':self.raw.stat().st_size}}}))
        m.drain()

    def test_drain_uses_the_same_instance_boundary_as_the_bridge(self):
        self.instance.write_text('{"epoch":"fixture","started":100}')
        old=self.logs/'1_file_connector_ndr_transmit';old.write_text('previous instance evidence\n');os.utime(old,(10,10))
        (self.logs/'2_alert_json.txt').touch()
        m.CHECKPOINT.write_text(json.dumps({'epoch':'fixture','files':{self.raw.name:{'inode':self.raw.stat().st_ino,'offset':self.raw.stat().st_size}}}))
        m.drain()
        self.assertEqual(old.read_text(),'previous instance evidence\n')

    def test_drain_still_rejects_unread_current_instance_records(self):
        m.CHECKPOINT.write_text('{"epoch":"fixture","files":{}}')
        with mock.patch.object(m.time,'monotonic',side_effect=[0,1,46]),mock.patch.object(m.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'did not drain'):m.drain()

    def test_drain_keeps_instance_snapshot_after_runtime_directory_is_removed(self):
        snapshot=json.loads(self.instance.read_text());self.instance.unlink()
        m.CHECKPOINT.write_text(json.dumps({'epoch':'fixture','files':{self.raw.name:{'inode':self.raw.stat().st_ino,'offset':self.raw.stat().st_size}}}))
        m.drain(snapshot)

    def context(self):
        stack=__import__('contextlib').ExitStack();self.addCleanup(stack.close)
        client=stack.enter_context(mock.patch('deployment_support.Client'));client.return_value.request.return_value={'ok':True}
        stack.enter_context(mock.patch('deployment_support.configuration_lock',return_value=nullcontext()))
        stack.enter_context(mock.patch.object(m,'active',return_value=True))
        commands=stack.enter_context(mock.patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,'')))
        drain=stack.enter_context(mock.patch.object(m,'drain'))
        ready=stack.enter_context(mock.patch.object(m,'ready'))
        return client,commands,drain,ready

    def test_activation_backs_up_raw_logs_and_preserves_engine_database_and_config(self):
        client,commands,drain,ready=self.context();before=[p.read_bytes() for p in (self.engine,self.config,self.database)]
        m.apply(self.release)
        self.assertEqual([p.read_bytes() for p in (self.engine,self.config,self.database)],before)
        self.assertEqual(self.library.read_bytes(),(self.release/'libips-response.so').read_bytes())
        self.assertIn('LD_PRELOAD='+str(self.library),self.override.read_text())
        preserved=list(self.logs.glob('.response-*/0_file_connector_ndr_transmit'));self.assertEqual(len(preserved),1)
        self.assertEqual(preserved[0].read_text(),'native evidence\n')
        self.assertIn(mock.call('systemctl','stop','ips'),commands.call_args_list)
        drain.assert_called_once();ready.assert_called_once()
        client.return_value.request.assert_any_call('maintenance',enabled=False)

    def test_failed_activation_restores_old_adapter_without_losing_raw_logs(self):
        self.library.parent.mkdir();self.library.write_bytes(b'old library');self.override.parent.mkdir();self.override.write_text('old override')
        client,commands,drain,ready=self.context();ready.side_effect=[RuntimeError('not ready'),None]
        with mock.patch.object(m.subprocess,'run'):
            with self.assertRaisesRegex(RuntimeError,'not ready'):m.apply(self.release)
        self.assertEqual(self.library.read_bytes(),b'old library');self.assertEqual(self.override.read_text(),'old override')
        self.assertTrue(any(p.read_text()=='native evidence\n' for p in self.logs.glob('.response-*/*')))
        self.assertEqual(self.engine.read_text(),'precompiled engine')
        client.return_value.request.assert_any_call('maintenance',enabled=False)

    def test_validation_failure_never_stops_detection(self):
        client,commands,drain,ready=self.context();commands.side_effect=RuntimeError('preflight')
        with self.assertRaisesRegex(RuntimeError,'preflight'):m.apply(self.release)
        self.assertNotIn(mock.call('systemctl','stop','ips'),commands.call_args_list)
        self.assertTrue(self.raw.exists());client.return_value.request.assert_any_call('maintenance',enabled=False)


if __name__=='__main__':unittest.main()
