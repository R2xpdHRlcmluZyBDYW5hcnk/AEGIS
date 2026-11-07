"""Telemetry must separate unavailable values, zero, and file inventory counts."""
import json
from unittest import mock
import unittest
from tests import test_rule_manager as fixture
import snort_engine


class TelemetryCase(unittest.TestCase):
    def test_inspection_limits_distinguish_absent_groups_from_zero_pegs(self):
        engine=snort_engine.SnortControl()
        stats=dict(sections=[dict(groups=[dict(name='stream_tcp',counters=[dict(name='gaps',value=7)]),
                                         dict(name='detection',counters=[])])])
        with mock.patch.object(engine,'command',return_value=json.dumps(stats)):
            counters=engine.call(['dump-counters'])['dump-counters']['inspection']
        self.assertEqual(counters['tcp_gaps'],7)
        self.assertEqual(counters['tcp_max_bytes'],0)
        self.assertEqual(counters['event_limit'],0)
        self.assertIsNone(counters['decoder_discards'])

    def test_nfqueue_backlog_and_both_loss_counters_are_independent(self):
        from event_processing import backend
        m=backend()
        rows='0 123 4 2 65535 5 7 900 1\n1 124 6 2 65535 11 13 901 1\n9 125 90 2 65535 99 99 902 1\n'
        with mock.patch('builtins.open',mock.mock_open(read_data=rows)):
            result=m.SysInfo._queue_listeners()
        self.assertEqual((result['count'],result['queue_total'],result['kernel_drops'],result['user_drops']),
                         (2,10,16,20))
        self.assertEqual(result['queues'][0],dict(id=0,backlog=4,kernel_drops=5,user_drops=7))
        system=m.SysInfo()
        with mock.patch.object(system,'_queue_listeners',return_value=None),\
             mock.patch.object(system,'_nft_queue_counter',return_value=(1000,2000)):
            result=system.queue()
        self.assertIsNone(result['queue_total']);self.assertIsNone(result['user_drops'])
        self.assertEqual(result['packets'],1000)

    def test_overview_preserves_backlog_instead_of_relabeling_cumulative_packets(self):
        from event_processing import backend
        m=backend();app=m.App.__new__(m.App);app.sys=mock.Mock()
        app.sys.service.return_value={};app.sys.counters.return_value={};app.sys.ruleset.return_value={}
        app.sys.queue.return_value=dict(packets=1000000,queue_total=3,kernel_drops=5,user_drops=7,listeners_known=True)
        queue=app.overview_runtime(panel=True)['queue']
        self.assertEqual(queue['queue_total'],3)
        self.assertEqual(queue['user_drops'],7)
        self.assertEqual(queue['packets'],1000000)

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
