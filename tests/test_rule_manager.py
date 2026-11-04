"""Protocol boundary, durable scheduling, serialized jobs and rollback behavior."""
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ips_control as control


def engine():
    loader = importlib.machinery.SourceFileLoader('rule_manager_fixture', str(ROOT / 'ips-web'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


class ManagerCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.module = engine()
        rules, config = self.base / 'rules', self.base / 'etc'
        rules.mkdir(); config.mkdir()
        for name in ('RULES_FILE', 'LOCAL_RULES', 'BAN_RULES', 'BAN_STORE', 'BAN_DETECTOR', 'HUNT_RULES'):
            setattr(self.module, name, str(rules / name))
        for name in ('THRESHOLD_CONF', 'SUPPRESS_LUA', 'DISABLE_CONF', 'DROP_CONF', 'MODIFY_CONF', 'ACTION_CONF', 'SNORT_CONF'):
            path = config / name
            path.write_text('')
            setattr(self.module, name, str(path))
        Path(self.module.RULES_FILE).write_text('alert ip any any -> any any (msg:"test"; sid:123; rev:1;)\n')
        Path(self.module.HUNT_RULES).write_text('')
        self.module.SOURCES_DIR = str(self.base / 'sources')
        self.module.UPDATE_CACHE_DIR = str(self.base / 'cache')
        self.module.DIST_RULES_DIR = str(self.base / 'dist')
        self.module.RULE_SCHEDULE = str(self.base / 'schedule.json')
        self.manager = control.Manager(self.module, str(self.base / 'state'))
        self.jobs = self.manager.app.sys

    def mutate(self, path, body=None, method='POST'):
        return self.manager.dispatch(dict(operation='mutate', method=method, path=path, body=body or {}))

    def wait(self):
        deadline = time.monotonic() + 3
        while self.manager.busy and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertFalse(self.manager.busy)
        return self.jobs.update_status()

    def test_protocol_rejects_arbitrary_commands_paths_engine_writes_and_extra_keys(self):
        for request in (
            dict(operation='exec', command='id'),
            dict(operation='read', name='app.__dict__', args=[], kwargs={}),
            dict(operation='read', name='governance_state', args=[], kwargs={'path':'/etc/shadow'}),
            dict(operation='snort', commands=['shutdown']),
            dict(operation='snort', commands=[['ruleset-reload-rules', {}]]),
            dict(operation='queue', table='filter'),
            dict(operation='mutate', method='POST', path='/api/db/clear', body={}),
            dict(operation='mutate', method='DELETE', path='/api/bans/../../etc/shadow', body={}),
            dict(operation='ping', command='id'),
        ):
            with self.subTest(request=request), self.assertRaises((ValueError, TypeError)):
                self.manager.dispatch(request)
        self.assertEqual(self.manager.dispatch({'operation':'ping'}), {'ready':True})

    def test_request_and_response_size_limits(self):
        for raw in (b'{}', b'{}\n' * 100):
            with self.assertRaises(ValueError):
                control.receive(io.BytesIO(raw), 2)
        with self.assertRaisesRegex(ValueError, 'too large'):
            control.Client().request('mutate', body='x' * control.REQUEST_LIMIT)

    def test_only_root_can_pause_jobs_for_atomic_backend_upgrades(self):
        request = dict(operation='maintenance',enabled=True)
        with self.assertRaises(ValueError):
            self.manager.dispatch(request,peer_uid=62000)
        self.assertTrue(self.manager.dispatch(request,peer_uid=0)['ok'])
        self.assertFalse(self.mutate('/api/actions/update')['ok'])
        self.assertFalse(self.jobs.update_rules()['ok'])
        self.assertTrue(self.manager.dispatch(dict(request,enabled=False),peer_uid=0)['ok'])
        self.manager.busy=True
        self.assertFalse(self.manager.dispatch(request,peer_uid=0)['ok'])

    def test_schedule_edits_persist_independently_of_web_and_remain_available_during_job(self):
        self.manager.busy = True
        setting = dict(enabled=True, frequency='weekly', weekday=2, time='05:43')
        result = self.mutate('/api/rules/schedule', setting)
        self.assertTrue(result['ok'])
        rebuilt = control.Manager(self.module, str(self.base / 'another-state'))
        status = rebuilt.dispatch({'operation':'schedule'})
        self.assertEqual(status['time'], '05:43')
        self.assertEqual(status['next_run'], result['next_run'])
        self.assertFalse(self.mutate('/api/actions/update')['ok'])
        with self.assertRaises(ValueError):
            self.mutate('/api/rules/schedule', dict(setting, time='25:00'))

    def test_success_validates_final_files_before_reloading_and_serializes_mutations(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def run(arguments, job, timeout=600):
            calls.append(arguments)
            if arguments[0].endswith('ips-snort-rules'):
                entered.set(); self.assertTrue(release.wait(2))
        with mock.patch.object(self.jobs, 'run', side_effect=run), \
                mock.patch.object(self.jobs.local.engine, 'call', return_value={'ruleset-reload-rules':{},'appid-reload-detectors':{}}) as reload:
            self.assertTrue(self.mutate('/api/actions/apply')['ok'])
            self.assertTrue(entered.wait(2))
            self.assertFalse(self.mutate('/api/rules/disable', {'values':['sid:123']})['ok'])
            self.assertEqual(self.manager.dispatch({'operation':'read', 'name':'sys.update_status', 'args':[], 'kwargs':{}})['state'], 'running')
            release.set()
            self.assertEqual(self.wait()['rc'], 0)
        self.assertEqual(calls[0], ['/usr/local/bin/ips-snort-rules', '--offline', '--no-reload'])
        self.assertEqual(calls[-1], ['/opt/ips-snort3/3.12.4.0/bin/snort', '-T', '-c', self.module.SNORT_CONF])
        self.assertIn(mock.call(['ruleset-reload-rules'],timeout=300),reload.call_args_list)
        self.assertEqual(list((self.base / 'state').glob('transaction-*')), [])

    def test_invalid_hunting_rule_restores_files_without_touching_running_engine(self):
        before = Path(self.module.HUNT_RULES).read_bytes()
        with mock.patch.object(self.jobs, 'run', side_effect=RuntimeError('invalid candidate')), \
                mock.patch.object(self.jobs.local.engine, 'call') as reload:
            self.assertTrue(self.mutate('/api/hunt/rules', {'rule':'alert ip any any -> any any (msg:"invalid"; sid:456;) '})['ok'])
            self.assertTrue(self.manager.drafts.dirty)
            self.assertEqual(Path(self.module.HUNT_RULES).read_bytes(), before)
            self.assertTrue(self.mutate('/api/actions/apply')['ok'])
            result = self.wait()
        self.assertEqual(result['rc'], 1)
        self.assertEqual(Path(self.module.HUNT_RULES).read_bytes(), before)
        reload.assert_not_called()
        self.assertTrue(self.manager.drafts.dirty)
        self.assertIn('sid:456', Path(self.manager.drafts.module.HUNT_RULES).read_text())

    def test_update_failure_restores_generated_rules_and_removes_new_files(self):
        original = Path(self.module.RULES_FILE).read_bytes()
        def fail(arguments, job, timeout=600):
            Path(self.module.RULES_FILE).write_text('bad generated file')
            (Path(self.module.RULES_FILE).parent / 'new.rules').write_text('bad')
            raise RuntimeError('download failed')
        with mock.patch.object(self.jobs, 'run', side_effect=fail):
            self.mutate('/api/actions/update')
            self.assertEqual(self.wait()['rc'], 1)
        self.assertEqual(Path(self.module.RULES_FILE).read_bytes(), original)
        self.assertFalse((Path(self.module.RULES_FILE).parent / 'new.rules').exists())

    def test_batch_delete_defers_all_files_until_explicit_application(self):
        Path(self.module.DISABLE_CONF).write_text('123\n456\n')
        self.manager.drafts.reset()
        with mock.patch.object(self.jobs, 'run') as run, \
                mock.patch.object(self.jobs.local.engine, 'call', return_value={'ruleset-reload-rules':{},'appid-reload-detectors':{}}) as reload:
            self.assertTrue(self.mutate('/api/rules/batch-delete', {'paths':[
                '/api/rules/disable/sid%3A123', '/api/rules/disable/sid%3A456']})['ok'])
            run.assert_not_called()
            reload.assert_not_called()
            self.assertEqual(Path(self.module.DISABLE_CONF).read_text(), '123\n456\n')
            self.assertEqual(Path(self.manager.drafts.module.DISABLE_CONF).read_text(), '')
            self.assertTrue(self.mutate('/api/actions/apply')['ok'])
            self.assertEqual(self.wait()['rc'], 0)
        self.assertEqual(Path(self.module.DISABLE_CONF).read_text(), '')
        self.assertTrue(any(command.args[0][-1] == self.module.SNORT_CONF for command in run.call_args_list))
        self.assertIn(mock.call(['ruleset-reload-rules'],timeout=300),reload.call_args_list)

    def test_group_suppression_removal_matches_all_sids_and_only_saves_drafts(self):
        m = self.manager.drafts.module
        rows = [dict(name='large',label='Large',source='active',source_enabled=True),
                dict(name='overlap',label='Overlap',source='active',source_enabled=True),
                dict(name='stopped',label='Stopped',source='old',source_enabled=False)]
        members = {('large','active'):set(range(1,352)),('overlap','active'):set(range(300,401))|{0},('stopped','old'):{401}}
        pending = m._PENDING_SUPPRESS + m.base64.urlsafe_b64encode(b'suppress gen_id 1, sig_id 401').decode() + '\n'
        preserved = '# keep\nthreshold gen_id 1, sig_id 123, type limit, track by_src, count 1, seconds 60\nsuppress gen_id 0, sig_id 123\nsuppress gen_id 1, sig_id 0\nsuppress gen_id 2, sig_id 123\n'
        original = preserved + ''.join('suppress gen_id 1, sig_id %d\n'%sid for sid in range(1,401)) + pending
        Path(self.module.THRESHOLD_CONF).write_text(original)
        self.manager.drafts.reset()
        with mock.patch.object(m,'rule_group_catalog',return_value=rows),mock.patch.object(m,'_GROUP_CACHE',dict(members=members)), \
                mock.patch.object(self.jobs,'run') as run,mock.patch.object(self.jobs.local.engine,'call') as reload:
            catalog = m.suppression_group_catalog(removable=True)
            self.assertEqual({r['name'] for r in catalog},{'large','overlap','stopped'})
            self.assertEqual(next(r for r in catalog if r['name']=='large')['removable'],len(members[('large','active')]))
            invalid = self.mutate('/api/rules/suppress-groups/remove',{'groups':['large','missing']})
            self.assertFalse(invalid['ok']);self.assertFalse(self.manager.drafts.dirty)
            self.assertEqual(Path(m.THRESHOLD_CONF).read_text(),original)
            result = self.mutate('/api/rules/suppress-groups/remove',{'groups':['large','overlap','large']})
            self.assertTrue(result['ok']);self.assertTrue(result['pending'])
            self.assertEqual(result['removed'],len(set(range(1,401))))
            self.assertEqual(Path(m.THRESHOLD_CONF).read_text(),preserved+pending)
            self.assertEqual(Path(self.module.THRESHOLD_CONF).read_text(),original)
            self.assertTrue(self.mutate('/api/rules/suppress-groups/remove',{'groups':['stopped']})['ok'])
            self.assertEqual(Path(m.THRESHOLD_CONF).read_text(),preserved)
            no_match = self.mutate('/api/rules/suppress-groups/remove',{'groups':['large']})
            self.assertTrue(no_match['ok']);self.assertEqual(no_match['removed'],0)
            self.assertEqual(m.suppression_group_catalog(removable=True),[])
            run.assert_not_called();reload.assert_not_called()

    def test_batch_selection_and_suppression_deletion_have_no_200_item_truncation(self):
        m = self.manager.drafts.module
        sids = list(range(1,502))
        original = '# keep\n'+''.join('suppress gen_id 1, sig_id %d\n'%sid for sid in sids)
        Path(self.module.THRESHOLD_CONF).write_text(original)
        self.manager.drafts.reset()
        self.assertEqual(m._batch_values(dict(sids=sids),'sids','sid'),list(map(str,sids)))
        with mock.patch.object(m,'atomic_text',wraps=m.atomic_text) as write, mock.patch.object(self.jobs,'run') as run:
            result = self.mutate('/api/rules/batch-delete',{'paths':['/api/rules/suppress/'+str(sid) for sid in sids]})
        self.assertTrue(result['ok']);write.assert_called_once();run.assert_not_called()
        self.assertEqual(Path(m.THRESHOLD_CONF).read_text(),'# keep\n')
        self.assertEqual(Path(self.module.THRESHOLD_CONF).read_text(),original)

    def test_batch_error_rolls_back_earlier_deletions(self):
        Path(self.module.DISABLE_CONF).write_text('123\n')
        self.manager.drafts.reset()
        with self.assertRaises(ValueError):
            self.mutate('/api/rules/batch-delete', {'paths':[
                '/api/rules/disable/sid%3A123', '/api/rules/disable/sid%3A999']})
        self.assertEqual(Path(self.module.DISABLE_CONF).read_text(), '123\n')
        self.assertEqual(Path(self.manager.drafts.module.DISABLE_CONF).read_text(), '123\n')
        self.assertFalse(self.manager.drafts.dirty)
        self.assertFalse(self.manager.busy)

    def test_rejected_duplicate_does_not_mark_lock_files_as_pending_edits(self):
        Path(self.module.DISABLE_CONF).write_text('123\n')
        self.manager.drafts.reset()
        result = self.mutate('/api/rules/disable', {'values':['sid:123']})
        self.assertFalse(result['ok'])
        self.assertFalse(self.manager.drafts.dirty)

    def test_interrupted_job_recovers_durable_snapshot_on_restart(self):
        original = Path(self.module.RULES_FILE).read_bytes()
        control.RuleBackup(self.module, self.manager.state)
        Path(self.module.RULES_FILE).write_text('interrupted output')
        with mock.patch.object(self.module.Snort, 'call', return_value={'ruleset-reload-rules':{},'appid-reload-detectors':{}}) as reload:
            rebuilt = control.Manager(self.module, self.manager.state)
        self.assertEqual(Path(self.module.RULES_FILE).read_bytes(), original)
        self.assertEqual(rebuilt.app.sys.update_status()['rc'], 1)
        reload.assert_called_once()

    def test_all_manual_mutations_are_persistent_drafts_without_engine_calls(self):
        with mock.patch.object(self.jobs, 'run') as run, mock.patch.object(self.jobs.local.engine, 'call') as reload:
            for path, body in (
                ('/api/rules/disable', {'values':['sid:123']}),
                ('/api/rules/action', {'selectors':['sid:456'],'action':'reject'}),
                ('/api/rules/drop', {'values':['group:emerging-*']}),
                ('/api/rules/reject', {'values':['group:emerging-*'],'replace':True}),
                ('/api/rules/suppress', {'sids':['123']}),
                ('/api/hunt/rules', {'rule':'alert ip any any -> any any (msg:"custom"; sid:456; rev:1;)'}),
                ('/api/bans', {'target':'192.0.2.1'}),
            ):
                with self.subTest(path=path):
                    self.assertTrue(self.mutate(path, body)['ok'])
            self.assertTrue(self.mutate('/api/rules/action-apply')['pending'])
            run.assert_not_called(); reload.assert_not_called()
        self.assertEqual(Path(self.module.DISABLE_CONF).read_text(), '')
        self.assertEqual(Path(self.module.HUNT_RULES).read_text(), '')
        rebuilt = control.Manager(self.module, self.manager.state)
        self.assertTrue(rebuilt.drafts.dirty)
        self.assertIn('456', Path(rebuilt.drafts.module.HUNT_RULES).read_text())
        self.assertIn('192.0.2.1', Path(rebuilt.drafts.module.BAN_STORE).read_text())
        self.assertTrue(self.mutate('/api/rules/pending/discard')['ok'])
        self.assertFalse(self.manager.drafts.dirty)
        self.assertEqual(Path(self.manager.drafts.module.HUNT_RULES).read_text(), '')

    def test_automatic_updates_use_active_configuration_and_keep_pending_edits(self):
        self.mutate('/api/rules/disable', {'values':['sid:123']})
        pending = self.manager.drafts.signature()
        seen = []
        def run(args, job, timeout=600):
            seen.append(Path(self.module.DISABLE_CONF).read_text())
        with mock.patch.object(self.jobs, 'run', side_effect=run), \
                mock.patch.object(self.jobs.local.engine, 'call', return_value={'ruleset-reload-rules':{},'appid-reload-detectors':{}}) as reload:
            for trigger in ('manual', 'scheduled'):
                self.assertTrue(self.jobs.update_rules(trigger=trigger)['ok'])
                result = self.wait()
                self.assertEqual(result['rc'], 0)
                self.assertTrue(result['pending'])
                self.assertIn('待应用更改仍保留', '\n'.join(result['lines']))
            self.assertTrue(seen); self.assertTrue(all(value == '' for value in seen))
            self.assertEqual(self.manager.drafts.signature(), pending)
            self.assertTrue(self.mutate('/api/actions/apply')['ok'])
            self.assertEqual(self.wait()['rc'], 0)
        self.assertFalse(self.manager.drafts.dirty)
        self.assertTrue(Path(self.module.DISABLE_CONF).read_text().startswith('123'))
        self.assertEqual(sum(call.args[0]==['ruleset-reload-rules'] for call in reload.call_args_list),3)

    def test_source_edits_use_private_metadata_until_application(self):
        with mock.patch.object(self.jobs, 'run') as run:
            self.assertTrue(self.mutate('/api/rules/source', {'name':'snort/community','enable':True})['ok'])
            run.assert_not_called()
        self.assertFalse(Path(self.module.SOURCES_DIR).exists())
        with mock.patch.object(self.jobs, 'run') as run, \
                mock.patch.object(self.jobs.local.engine, 'call', return_value={'ruleset-reload-rules':{},'appid-reload-detectors':{}}):
            self.assertTrue(self.mutate('/api/actions/apply')['ok'])
            self.assertEqual(self.wait()['rc'], 0)
        self.assertIn('--offline', run.call_args_list[0].args[0])
        self.assertTrue((Path(self.module.SOURCES_DIR) / 'snort-community.yaml').exists())

    def test_committed_recovery_clears_drafts_without_reloading_or_reverting(self):
        self.mutate('/api/rules/disable', {'values':['sid:123']})
        backup = control.RuleBackup(self.module, self.manager.state)
        self.manager.drafts.promote()
        backup.commit(clear_pending=True)
        with mock.patch.object(self.module.Snort, 'call') as reload:
            rebuilt = control.Manager(self.module, self.manager.state)
        reload.assert_not_called()
        self.assertFalse(rebuilt.drafts.dirty)
        self.assertTrue(Path(self.module.DISABLE_CONF).read_text().startswith('123'))

    def test_source_edits_never_invoke_updater_or_write_active_data(self):
        with mock.patch.object(self.module.SysInfo, 'run', return_value=(0,'','')) as run:
            manager = control.Manager(self.module, str(self.base / 'cli-state'))
            self.assertTrue(manager.dispatch(dict(operation='mutate',method='POST',path='/api/rules/source',body={'name':'snort/community','enable':True}))['ok'])
        run.assert_not_called()
        self.assertTrue((manager.drafts.sources/'snort-community.yaml').exists())
        self.assertFalse(Path(self.module.SOURCES_DIR).exists())

    def test_applied_rules_are_not_rolled_back_if_draft_state_sync_fails(self):
        self.mutate('/api/rules/disable', {'values':['sid:123']})
        with mock.patch.object(self.jobs,'run'), mock.patch.object(self.jobs.local.engine,'call',return_value={'ruleset-reload-rules':{},'appid-reload-detectors':{}}), \
                mock.patch.object(self.manager.drafts,'reset',side_effect=OSError('state sync failed')):
            self.assertTrue(self.mutate('/api/actions/apply')['ok'])
            self.assertEqual(self.wait()['rc'],1)
        self.assertTrue(self.manager.paused)
        self.assertTrue(list(Path(self.manager.state).glob('transaction-*')))
        with mock.patch.object(self.module.Snort,'call') as reload:
            rebuilt = control.Manager(self.module,self.manager.state)
        reload.assert_not_called()
        self.assertFalse(rebuilt.drafts.dirty)
        self.assertTrue(Path(self.module.DISABLE_CONF).read_text().startswith('123'))

    def test_unix_socket_round_trip_and_invalid_request(self):
        if not hasattr(socket, 'AF_UNIX'):
            self.skipTest('Unix sockets unavailable')
        path = str(self.base / 'control.sock')
        with control.Server(path, self.manager) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.assertTrue(control.Client(path).request('ping')['ready'])
                with self.assertRaises(RuntimeError):
                    control.Client(path).request('exec', command='id')
            finally:
                server.shutdown(); thread.join()

    def test_web_proxies_do_not_open_rules_or_engine_socket(self):
        client = mock.Mock()
        runtime=mock.Mock()
        control.install_proxies(self.module, client,runtime)
        self.module.governance_state(details=True)
        client.request.assert_called_with('read', name='governance_state', args=(), kwargs={'details':True})
        self.module.Snort('/forbidden').call(['version'])
        runtime.engine_call.assert_called_once_with(['version'],10)
        control.RemoteSchedule(client).status()
        client.request.assert_called_with('schedule')

    @unittest.skipUnless(os.name == 'posix', 'Rule subprocess runner targets Linux')
    def test_subprocess_runner_collects_output_and_terminates_on_deadline(self):
        job = self.jobs.rule_job
        self.jobs.run([sys.executable, '-c', 'print("fixture output")'], job, timeout=3)
        self.assertIn('fixture output', job['lines'])
        with self.assertRaisesRegex(RuntimeError, '退出码 2'):
            self.jobs.run([sys.executable, '-c', 'raise SystemExit(2)'], job, timeout=3)
        with self.assertRaises(TimeoutError):
            self.jobs.run([sys.executable, '-c', 'import time; time.sleep(10)'], job, timeout=.05)


if __name__ == '__main__':
    unittest.main()
