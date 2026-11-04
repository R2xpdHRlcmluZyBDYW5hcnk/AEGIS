"""MITRE searches must use logged metadata, including persisted historical alerts."""
import datetime
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('mitre_backend', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


class MitreAttackCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = m.EventDB(str(Path(self.temp.name) / 'events.db'))
        self.store = m.EventStore(str(Path(self.temp.name) / 'eve.json'))
        self.store.db = self.db
        self.app = m.App.__new__(m.App)
        self.app.db, self.app.store = self.db, self.store
        self.stamp = m.now() - 1000
        self.index = 0

    def tearDown(self):
        self.db.conn.close()
        self.temp.cleanup()

    def add(self, metadata=None, etype='alert', flow=777, signature='Example', offset=None):
        self.index += 1
        stamp = self.stamp + (self.index if offset is None else offset)
        data = dict(timestamp=datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat(),
                    event_type=etype, flow_id=flow, community_id='fixture:'+str(flow), src_ip='192.0.2.1', src_port=12345,
                    dest_ip='198.51.100.1', dest_port=443, proto='TCP', app_proto='tls',
                    snort_native=dict(session_id='a'*32+':'+format(flow,'016x')))
        if etype == 'alert':
            data['alert'] = dict(signature=signature, signature_id=42, severity=2, action='allowed', rev=1)
            if metadata is not None:
                data['alert']['metadata'] = metadata
        record, raw = m.EventStore._parse(json.dumps(data).encode())
        self.db.add(record, raw.decode('utf-8'))
        return record

    def search(self, query):
        self.db.flush()
        return self.app.hunt({'q': query, 'all': '1', 'source': 'db', 'icase': '1'})

    def test_normalizes_strings_arrays_duplicates_and_invalid_ids(self):
        data = {'alert': {'metadata': {'mitre_tactic_id': ['ta0011', 'TA0011', '<script>'],
                'mitre_technique_id': 'T1059.001, T1568', 'mitre_tactic_name': ['Command_And_Control', None]}}}
        self.assertEqual(m.attack_metadata(data), {'mitre_tactic_id': ['TA0011'],
            'mitre_technique_id': ['T1059.001', 'T1568'], 'mitre_tactic_name': ['Command_And_Control']})
        for value in (None, [], {}, {'alert': 'invalid'}, {'alert': {'metadata': []}}):
            self.assertEqual(m.attack_metadata(value), {})

    def test_database_search_reads_historical_raw_without_memory_or_schema_changes(self):
        columns = list(self.db.conn.execute('PRAGMA table_info(events)'))
        self.add({'mitre_tactic_id': ['TA0011'], 'mitre_technique_id': ['T1568', 'T1059.001'],
                  'mitre_technique_name': ['Dynamic_Resolution']})
        self.add(signature='Same signature without mapping')
        self.assertEqual(len(self.store.events), 0)
        result = self.search('mitre_tactic_id:ta0011 AND mitre_technique_id:T1568')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['events'][0]['mitre_technique_id'], ['T1568', 'T1059.001'])
        self.assertIn('metadata', result['events'][0]['_raw'])
        self.assertFalse(result.get('truncated'))
        self.assertEqual(columns, list(self.db.conn.execute('PRAGMA table_info(events)')))

    def test_subtechniques_match_exact_ids_and_explicit_wildcards(self):
        self.add({'mitre_technique_id': ['T1059.001']})
        self.assertEqual(self.search('mitre_technique_id:T1059')['total'], 0)
        self.assertEqual(self.search('mitre_technique_id:T1059.*')['total'], 1)
        self.assertEqual(self.search('mitre_technique_id:T1059.001')['total'], 1)

    def test_empty_existence_not_or_and_name_search(self):
        self.add({'mitre_tactic_id': ['TA0011'], 'mitre_technique_name': ['Dynamic_Resolution']})
        self.add({'mitre_tactic_id': []})
        self.add(etype='dns')
        self.assertEqual(self.search('mitre_tactic_id:*')['total'], 1)
        self.assertEqual(self.search('NOT mitre_tactic_id:*')['total'], 2)
        self.assertEqual(self.search('mitre_tactic_id:TA0011 OR type:dns')['total'], 2)
        self.assertEqual(self.search('type:alert AND NOT mitre_tactic_id:TA0011')['total'], 1)
        self.assertEqual(self.search('mitre_technique_name:resolution')['total'], 1)
        self.assertEqual(self.search('mitre_technique_name:*Reso*')['total'], 1)

    def test_mapping_aggregates_all_alerts_beyond_evidence_page_limit(self):
        self.add({'mitre_tactic_id': ['TA0011'], 'mitre_technique_id': ['T1568']})
        for _ in range(501):
            self.add({'mitre_tactic_id': ['TA0002'], 'mitre_technique_id': ['T1059.001']})
        self.add({'mitre_tactic_id': ['TA0040']}, flow=999)
        self.db.flush()
        detail = self.db.security_incident('session:'+'a'*32+':'+format(777,'016x'), self.stamp, m.now())
        self.assertEqual(len(detail['alerts']), 500)
        self.assertTrue(detail['truncated'])
        self.assertEqual(set(detail['attack']['mitre_tactic_id']), {'TA0011', 'TA0002'})
        self.assertEqual(set(detail['attack']['mitre_technique_id']), {'T1568', 'T1059.001'})

    def test_finite_type_options_match_ingestion_types_and_examples_parse(self):
        fields = {field['name']: field for field in m.App.hunt_schema()['fields']}
        self.assertTrue(set(m.MITRE_FIELDS).issubset(fields))
        self.assertEqual({item['value'] for item in fields['type']['values']}, {'alert','drop','dns','http','tls','anomaly','fileinfo','flow','session','quic','ssh','ftp'})
        self.assertEqual({item['value'] for item in fields['level']['values']}, {'high', 'medium', 'low','unknown'})
        for field in fields.values():
            for item in field.get('values', []):
                with self.subTest(field=field['name'], value=item['value']):
                    node = m.hunt_parse(field['name'] + ':' + json.dumps(item['value']))
                    self.assertTrue(m.hunt_match(node, {m.HUNT_FIELDS[field['name']]: item['value']}))


if __name__ == '__main__':
    unittest.main()
