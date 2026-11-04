"""Clear history only after stopping writers; preserve all operational settings."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import history_reset as reset
from tests import test_rule_manager as fixture


class HistoryResetTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.web=self.root/'web';self.native=self.root/'native';self.events=self.root/'events'
        self.state=self.root/'manager';self.bridge=self.root/'bridge'
        for path in (self.web,self.native,self.events,self.state,self.bridge):path.mkdir()
        self.stream=self.events/'events.json';self.checkpoint=self.bridge/'offsets.json'
        self.database=self.web/'snort-ndr.db'
        self.history=[Path(str(self.database)+s) for s in ('','-wal','-shm','.summary.db','.summary.db-wal','.summary.db-shm')]
        self.history += [self.native/'1_file_connector_ndr_transmit',self.native/'2_alert_json.txt.1.gz',self.stream,self.events/'events.json.1',self.checkpoint]
        self.protected=[self.web/'settings.json',self.web/'authentication.json',self.native/'engine.log',self.bridge/'rules.conf']
        for path in self.history+self.protected:path.write_text('preserve-or-clear')
        patch=mock.patch.multiple(reset,WEB_STATE=self.web,NATIVE=self.native,STREAM=self.stream,CHECKPOINT=self.checkpoint)
        patch.start();self.addCleanup(patch.stop)

    def test_cleanup_removes_only_verified_history_and_projection(self):
        archive=self.native/'.response-20261104T010000-123';archive.mkdir()
        (archive/'0_file_connector_ndr_transmit').write_text('old raw evidence')
        reset.remove_history_files(self.database)
        self.assertFalse(archive.exists())
        self.assertTrue(all(not p.exists() for p in self.history))
        self.assertTrue(all(p.read_text()=='preserve-or-clear' for p in self.protected))

    def test_invalid_database_or_log_never_partially_deletes_history(self):
        with self.assertRaises(ValueError):reset.remove_history_files(self.root/'other/snort-ndr.db')
        self.assertTrue(all(p.exists() for p in self.history))
        if hasattr(__import__('os'),'geteuid'):
            bad=self.native/'3_file_connector_ndr_transmit';bad.symlink_to(self.protected[0])
            with self.assertRaises(ValueError):reset.remove_history_files(self.database)
            self.assertTrue(all(p.exists() for p in self.history))

    def queued(self):
        job='a'*32;reset.save(self.state,dict(id=job,state='queued'));return job

    def test_stop_all_writers_then_clear_and_restart_from_empty_inputs(self):
        job=self.queued();calls=[]
        def command(*args):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,stdout='0\n')
        cleanup=reset.remove_history_files
        def remove(path):
            self.assertEqual([c[:3] for c in calls if c[:2]==('systemctl','stop')][-3:],[('systemctl','stop','ips'),('systemctl','stop','ips-event-bridge'),('systemctl','stop','ips-web')])
            cleanup(path)
        with mock.patch.object(reset,'command',side_effect=command),mock.patch.object(reset,'active',return_value=True),mock.patch.object(reset,'web_ready',return_value=True),\
             mock.patch.object(reset,'remove_history_files',side_effect=remove),mock.patch('ips_control.Client') as client,\
             mock.patch('snort_engine.SnortControl') as engine,mock.patch.object(reset.os,'chown',create=True):
            client.return_value.request.return_value={'ok':True}
            reset.run(self.state,job)
        self.assertEqual(reset.status(self.state)['state'],'done')
        self.assertEqual(self.stream.read_bytes(),b'')
        self.assertFalse(self.checkpoint.exists())
        self.assertTrue(all(p.exists() for p in self.protected))
        self.assertIn(('systemctl','start','ips'),calls)
        client.return_value.request.assert_has_calls([mock.call('history-reset-begin',job=job),mock.call('history-reset-finish',job=job)])

    def test_failed_stop_preserves_history_and_attempts_service_recovery(self):
        job=self.queued()
        with mock.patch.object(reset,'command',return_value=mock.Mock(stdout='0')),mock.patch.object(reset,'active',return_value=False),\
             mock.patch.object(reset,'stop',side_effect=RuntimeError('stop failed')),mock.patch('ips_control.Client') as client,\
             mock.patch.object(reset.subprocess,'run') as recover:
            client.return_value.request.return_value={'ok':True}
            with self.assertRaisesRegex(RuntimeError,'stop failed'):reset.run(self.state,job)
        self.assertTrue(all(p.exists() for p in self.history))
        self.assertEqual(reset.status(self.state)['state'],'failed')
        self.assertIn('ips-web',recover.call_args.args[0])
        client.return_value.request.assert_any_call('history-reset-finish',job=job)

    def test_covered_storage_is_rejected_before_stopping_writers_or_removing_history(self):
        job=self.queued()
        with mock.patch.object(reset,'validate_log_storage',side_effect=RuntimeError('covered storage')), \
             mock.patch.object(reset,'command') as command,mock.patch.object(reset,'remove_history_files') as remove, \
             mock.patch('ips_control.Client') as client:
            client.return_value.request.return_value={'ok':True}
            with self.assertRaisesRegex(RuntimeError,'covered storage'):reset.run(self.state,job)
        command.assert_not_called();remove.assert_not_called()
        self.assertTrue(all(path.exists() for path in self.history))
        self.assertEqual(reset.status(self.state)['state'],'failed')
        client.return_value.request.assert_any_call('history-reset-finish',job=job)

    def test_repeated_resets_keep_settings_and_validate_storage_each_time(self):
        with mock.patch.object(reset,'command',return_value=mock.Mock(stdout='0')), \
             mock.patch.object(reset,'active',return_value=True),mock.patch.object(reset,'web_ready',return_value=True), \
             mock.patch.object(reset,'validate_log_storage') as validate,mock.patch('ips_control.Client') as client, \
             mock.patch('snort_engine.SnortControl'),mock.patch.object(reset.os,'chown',create=True):
            client.return_value.request.return_value={'ok':True}
            for _ in range(2):
                reset.run(self.state,self.queued())
                self.assertEqual(reset.status(self.state)['state'],'done')
        self.assertEqual(validate.call_count,4)
        self.assertTrue(all(path.read_text()=='preserve-or-clear' for path in self.protected))

    def test_queue_serializes_rule_jobs_and_requires_root_to_finish(self):
        case=fixture.ManagerCase();case.setUp();self.addCleanup(case.doCleanups)
        manager=case.manager
        with mock.patch.object(reset.subprocess,'run') as launch:
            result=manager.dispatch({'operation':'history-reset'})
        self.assertTrue(result['pending']);self.assertTrue(manager.paused)
        self.assertEqual(launch.call_count,1)
        self.assertFalse(manager.dispatch({'operation':'history-reset'})['ok'])
        self.assertFalse(manager.dispatch({'operation':'maintenance','enabled':True},peer_uid=0)['ok'])
        self.assertFalse(manager.jobs.update_rules()['ok'])
        request=dict(operation='history-reset-begin',job=result['reset_id'])
        with self.assertRaises(ValueError):manager.dispatch(request,peer_uid=62000)
        self.assertTrue(manager.dispatch(request,peer_uid=0)['ok'])
        reset.save(manager.state,dict(id=result['reset_id'],state='done'))
        manager.dispatch(dict(request,operation='history-reset-finish'),peer_uid=0)
        self.assertFalse(manager.paused)

    def test_failed_schedule_unpauses_manager_without_clearing_data(self):
        case=fixture.ManagerCase();case.setUp();self.addCleanup(case.doCleanups)
        with mock.patch.object(reset.subprocess,'run',side_effect=OSError('scheduler unavailable')):
            with self.assertRaises(OSError):case.manager.dispatch({'operation':'history-reset'})
        self.assertFalse(case.manager.paused)
        self.assertEqual(reset.status(case.manager.state)['state'],'failed')


if __name__=='__main__':unittest.main()
