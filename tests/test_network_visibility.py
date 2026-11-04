"""Flow ingestion, retained metadata, exact network aggregates and range boundaries."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('network_visibility_backend', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
backend = importlib.util.module_from_spec(spec)
loader.exec_module(backend)


class NetworkVisibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = backend.EventDB(str(Path(self.temp.name) / 'events.db'))

    def tearDown(self):
        self.db.conn.close()
        self.temp.cleanup()

    def add(self, kind, timestamp=1700000000, **fields):
        obj = dict(timestamp=backend.iso(timestamp), event_type=kind, src_ip='192.0.2.1', dest_ip='198.51.100.1', src_port=12345, dest_port=443, proto='TCP', app_proto='tls', flow_id=123, **fields)
        parsed = backend.EventStore._parse(json.dumps(obj))
        self.assertIsNotNone(parsed)
        self.db.add(*parsed)
        self.db.flush()
        return parsed[0]

    def test_flow_is_retained_and_searchable_without_mixing_security_counts(self):
        flow = dict(bytes_toserver=1000, bytes_toclient=2000, pkts_toserver=10, pkts_toclient=20, start=backend.iso(1699999940), end=backend.iso(1700000000), age=60, state='closed', reason='timeout')
        self.add('flow', flow=flow)
        total, records = self.db.search_range(1699999900, 1700000100, types=['flow'])
        self.assertEqual(total, 1)
        self.assertEqual(records[0]['bytes_toserver'], 1000)
        self.assertEqual(records[0]['flow_start'], 1699999940)
        self.assertEqual(records[0]['state'], 'closed')
        result = self.db.network_summary(1699999900, 1700000100)
        self.assertEqual((result['flows'],result['bytes'],result['addresses'],result['bidirectional']), (1,3000,2,1))
        self.assertEqual(result['applications'],[dict(name='tls',count=1)])
        self.assertEqual(self.db.security_summary(start=1699999900,end=1700000100)['total'],0)
        self.assertIn('flow',[value for value,_ in backend.HUNT_VALUE_OPTIONS['type']])
        store = backend.EventStore(str(Path(self.temp.name)/'eve.json'))
        store.db = self.db
        app = backend.App.__new__(backend.App)
        app.db,app.store = self.db,store
        for field,value in dict(bytes_toserver=1000,bytes_toclient=2000,pkts_toserver=10,pkts_toclient=20,flow_start=1699999940,flow_end=1700000000,flow_age=60).items():
            for space in ('', ' '):
                with self.subTest(field=field,space=space):
                    result = app.hunt(dict(q='type: flow AND '+field+':'+space+'>='+str(value), **{'from':'1699999900','to':'1700000100'}))
                    self.assertEqual(result['total'],1)
                    self.assertFalse(result.get('truncated'))

    def test_protocol_metadata_is_aggregated_without_alert_double_counting(self):
        self.add('dns', dns=dict(queries=[dict(rrname='example.test',rrtype='A')],type='request'))
        self.add('tls', tls=dict(sni='example.test',version='TLS 1.3'))
        self.add('alert', alert=dict(signature='test',signature_id=1,severity=1))
        result=self.db.network_summary(1699999999,1700000001)
        self.assertEqual((result['records'],result['dns'],result['tls'],result['flows']),(3,1,1,0))
        self.assertEqual(result['bytes'],0)
        self.assertEqual(result['dns_names'],[dict(name='example.test',count=1)])
        self.assertEqual(result['tls_names'],[dict(name='example.test',count=1)])

    def test_failed_application_detection_is_separate_from_flow_state(self):
        for state in ('new', 'established', 'closed', 'bypassed', 'future_state', ''):
            with self.subTest(state=state):
                raw = json.dumps(dict(timestamp=backend.iso(1700000000), event_type='flow',
                                      proto='UDP', app_proto='failed',
                                      flow=dict(state=state, reason='timeout', pkts_toserver=1, pkts_toclient=1)))
                record, retained = backend.EventStore._parse(raw)
                expected = '连接 UDP' + (' [ %s ]' % state if state else '') + ' 应用协议识别失败'
                if not state:
                    expected += ' 结束原因：timeout'
                self.assertEqual(record['sig'], expected)
                self.assertEqual((record['app'], record['state'], record['reason']), ('failed', state, 'timeout'))
                self.assertEqual(retained, raw)
                self.assertEqual(backend.list_record(record)['sig'], expected)
                self.assertNotIn('\\u00b7', json.dumps(record, ensure_ascii=True))

    def test_historical_flow_labels_are_normalized_without_rewriting_evidence(self):
        record = self.add('flow', flow=dict(state='established',reason='timeout'))
        self.db.conn.execute("UPDATE events SET app='failed',proto='UDP',sig=? WHERE type='flow'",
                             ('连接 failed \u00b7 established',))
        self.db.conn.commit()
        before = self.db.conn.execute('SELECT event_key,sig,app,state,reason,raw FROM events').fetchall()
        expected = '连接 UDP [ established ] 应用协议识别失败'
        for list_view in (False, True, 'network'):
            _, rows = self.db.search_range(1699999999,1700000001,list_view=list_view)
            self.assertEqual(rows[0]['sig'], expected)
            if list_view:
                detail = self.db.read_record(rows[0]['record_id'])
                self.assertEqual(detail['record']['sig'], expected)
                self.assertEqual(detail['raw']['sig'], expected)
        row = self.db.conn.execute('SELECT '+', '.join(self.db.names)+' FROM events').fetchone()
        self.assertEqual(self.db._row_lite(row, {'sig'})['sig'], expected)
        store = backend.EventStore(str(Path(self.temp.name)/'eve.json'))
        store.db = self.db
        store.ingest = lambda: None
        app = backend.App.__new__(backend.App)
        app.db, app.store = self.db, store
        for view in ('list', ''):
            result = app.events({'q':expected,'from':'1699999999','to':'1700000001','view':view})
            self.assertEqual(result['total'],1)
            self.assertEqual(result['events'][0]['sig'],expected)
            self.assertIn(expected,backend.events_csv(result['events']))
        self.db._hunt_functions()
        for query in ('sig:"[ established ]"','"应用协议识别失败"','sig:"连接 UDP"',
                      'app:failed AND state:established','sig:"连接 failed"','NOT sig:"[ closed ]"'):
            predicate = backend.hunt_parse(query)
            clauses,args,complete = backend.hunt_sql_pushdown(predicate)
            self.assertTrue(complete)
            actual = self.db.conn.execute('SELECT COUNT(*) FROM events WHERE '+' AND '.join(clauses),args).fetchone()[0]
            legacy = dict(record,app='failed',proto='UDP',sig='连接 failed \u00b7 established')
            self.assertEqual(actual,int(backend.hunt_match(predicate,legacy)),query)
        self.assertEqual(self.db.conn.execute('SELECT event_key,sig,app,state,reason,raw FROM events').fetchall(),before)

    def test_legacy_flow_counters_and_external_signatures_are_preserved(self):
        for signature in ('连接 established \u00b7 804 → 72 bytes \u00b7 0s',
                          '连接 http \u00b7 established \u00b7 804 → 72 bytes \u00b7 0s'):
            expected = '连接 http [ established ] 804 → 72 bytes 0s'
            formatted = backend.flow_summary('http','TCP','','',signature)
            self.assertEqual(formatted, expected)
            self.assertEqual(backend.flow_summary('http','TCP','','',formatted),expected)
        self.add('alert',alert=dict(signature='Vendor \u00b7 signature',signature_id=1,severity=1))
        _, rows = self.db.search_range(1699999999,1700000001,list_view=True)
        self.assertEqual(rows[0]['sig'],'Vendor \u00b7 signature')
        self.assertFalse(backend.hunt_match(backend.hunt_parse('None'),{'type':'alert'}))

    def test_custom_ranges_are_exact_and_never_reused_after_a_shift(self):
        self.add('flow', timestamp=1700000000,flow=dict(pkts_toserver=1,pkts_toclient=0))
        self.add('flow', timestamp=1700000010,flow=dict(pkts_toserver=1,pkts_toclient=0))
        a=self.db.network_summary(1700000000,1700000001)
        b=self.db.network_summary(1700000011,1700000012)
        self.assertEqual((a['flows'],a['one_way'],b['flows']),(1,1,0))

    def test_invalid_flow_counters_do_not_interrupt_ingestion(self):
        self.add('flow',flow=dict(bytes_toserver='invalid',age=[]))
        self.assertEqual(self.db.network_summary(1699999999,1700000001)['flows'],1)

    def test_http_versions_use_evidence_and_leave_legacy_storage_untouched(self):
        raw = json.dumps(dict(timestamp=backend.iso(1700000000), event_type='quic', app_proto='quic', quic=dict(version='1')))
        record, _ = backend.EventStore._parse(raw)
        self.assertEqual(record['httpver'], '')
        record['httpver'] = 'HTTP/3'
        self.db.add(record, raw)
        http2 = json.dumps(dict(timestamp=backend.iso(1700000001), event_type='http', app_proto='http2', http=dict(version='2', http_method='GET')))
        second, _ = backend.EventStore._parse(http2)
        self.assertEqual(second['httpver'], 'HTTP/2')
        second['httpver'] = ''
        self.db.add(second, http2);self.db.flush()
        before = self.db.conn.execute('SELECT event_key,httpver,raw FROM events ORDER BY rowid').fetchall()
        _, rows = self.db.search_range(1699999999,1700000002)
        self.assertEqual({row['type']:row['httpver'] for row in rows}, {'quic':'','http':'HTTP/2'})
        for query, expected in [('httpver:HTTP/3',0),('httpver:HTTP/2',1),('type:quic AND httpver:*',0),('NOT httpver:*',1)]:
            predicate = backend.hunt_parse(query)
            self.assertEqual(sum(backend.hunt_match(predicate, row) for row in rows), expected)
            where,args,full = backend.hunt_sql_pushdown(predicate)
            self.assertTrue(full)
            self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM events WHERE '+ ' AND '.join(where),args).fetchone()[0],expected)
        self.assertEqual(self.db.conn.execute('SELECT event_key,httpver,raw FROM events ORDER BY rowid').fetchall(),before)

    def test_file_transaction_id_and_current_ike_event_are_retained(self):
        raw = json.dumps(dict(timestamp=backend.iso(1700000000),event_type='fileinfo',fileinfo=dict(filename='test.bin',state='CLOSED',tx_id=0)))
        record, _ = backend.EventStore._parse(raw)
        self.assertEqual(record['tx'],0)
        raw = json.dumps(dict(timestamp=backend.iso(1700000000),event_type='ike',ike=dict(version='2')))
        record, _ = backend.EventStore._parse(raw)
        self.assertEqual(record['app'],'ike')

    def test_existing_database_migration_preserves_events_and_unknown_metrics(self):
        class LegacyDB(backend.EventDB):
            COLUMNS = [(column,key) for column,key in backend.EventDB.COLUMNS if column not in backend.FLOW_METRIC_FIELDS]
        path = str(Path(self.temp.name)/'legacy.db')
        old = LegacyDB(path)
        raw = json.dumps(dict(timestamp=backend.iso(1700000000),event_type='tls',src_ip='192.0.2.1',dest_ip='198.51.100.1',tls=dict(sni='retained.test')))
        old.add(*backend.EventStore._parse(raw));old.flush()
        before = old.conn.execute('SELECT event_key,ts,sni FROM events').fetchall()
        old.conn.close()
        updated = backend.EventDB(path)
        try:
            self.assertEqual(updated.conn.execute('SELECT event_key,ts,sni FROM events').fetchall(),before)
            self.assertEqual(updated.conn.execute('SELECT flow_start,bytes_toserver FROM events').fetchone(),(None,None))
        finally:
            updated.conn.close()

    def test_lazy_chart_route_requires_authentication_and_rejects_paths(self):
        handler = backend.Handler.__new__(backend.Handler)
        handler.command = 'GET'
        handler.path = '/chunk-ABC123.js'
        handler._static = mock.Mock()
        handler._require = mock.Mock(return_value=False)
        handler.do_GET()
        handler._static.assert_not_called()
        handler._require.return_value = True
        handler.do_GET()
        handler._static.assert_called_once_with('chunk-ABC123.js')
        handler._static.reset_mock()
        handler._error = mock.Mock()
        handler.path = '/chunk-../../ips-web.conf'
        handler.do_GET()
        handler._static.assert_not_called()


if __name__=='__main__':
    unittest.main()
