"""Telemetry must separate unavailable values, zero, and file inventory counts."""
import json
from unittest import mock
import unittest
from tests import test_rule_manager as fixture
import snort_engine


class TelemetryCase(unittest.TestCase):
    def test_native_tcp_memory_maps_to_real_counter_and_missing_stays_unknown(self):
        engine=snort_engine.SnortControl()
        stats=dict(sections=[dict(groups=[dict(name='stream_tcp',counters=[dict(name='memory',value=4096)])])])
        with mock.patch.object(engine,'command',return_value=json.dumps(stats)):
            counters=engine.call(['dump-counters'])['dump-counters']
        self.assertEqual(counters['tcp']['memory'],4096)
        self.assertIsNone(counters['flow']['memuse'])
        with mock.patch.object(engine,'command',return_value='{"sections":[]}'):
            self.assertIsNone(engine.call(['dump-counters'])['dump-counters']['tcp']['memory'])

    def test_ruleset_reports_file_inventory_without_inventing_failure_count(self):
        engine=snort_engine.SnortControl()
        with mock.patch.object(engine,'command',return_value='generation 1'),mock.patch.object(snort_engine,'rule_metadata',return_value={1:{},2:{}}):
            row=engine.call(['ruleset-stats'])['ruleset-stats']
        self.assertEqual((row['rules_loaded'],row['rules_loaded_source']),(2,'rule_files'))
        self.assertIsNone(row['rules_failed']);self.assertIsNone(row['rules_skipped'])

    def test_system_service_uses_privileged_read_boundary_and_failed_reads_are_explicit(self):
        test=fixture.ManagerCase();test.setUp();self.addCleanup(test.doCleanups)
        service=dict(state='active',pid=123,uptime=90,memory=4096,cpu_seconds=0)
        test.manager.runtime.service=service
        status=test.base/'status.json';test.manager.runtime.publish(status)
        from ips_control import install_proxies
        class Client:
            def request(self,operation,**parameters):return test.manager.dispatch(json.loads(json.dumps(dict(operation=operation,**parameters))))
        from runtime_status import RuntimeReader
        install_proxies(test.module,Client(),RuntimeReader(status))
        sys=test.module.SysInfo()
        self.assertEqual(sys.service(),service)
        with mock.patch.object(sys.engine,'call',return_value={'__error__':'socket unavailable'}):
            self.assertEqual(sys.engine_meta()['error'],'socket unavailable')
            self.assertEqual(sys.engine_meta()['uptime'],90)
            self.assertIsNone(sys.ruleset()['rules_failed'])
            self.assertIn('socket unavailable',sys.ruleset()['error'])


if __name__=='__main__':unittest.main()
