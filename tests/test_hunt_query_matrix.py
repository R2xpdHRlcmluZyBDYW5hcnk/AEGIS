"""Every public query field must agree across memory and complete database filtering."""
import datetime
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('hunt_matrix_backend', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


def literal(value):
    return json.dumps(str(value), ensure_ascii=False)


class HuntQueryMatrix(unittest.TestCase):
    def test_quoted_shortcut_values_preserve_quotes_backslashes_and_unicode(self):
        for value in ('test "quoted" reason', "single ' reason", r'C:\test\path', '中文 (blocked)'):
            for spacing in ('', ' '):
                query = 'type: drop AND reason:' + spacing + literal(value)
                node = m.hunt_parse(query)
                self.assertTrue(m.hunt_match(node, dict(type='drop', reason=value)))
                self.assertFalse(m.hunt_match(node, dict(type='drop', reason='different')))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = m.EventDB(str(Path(self.temp.name) / 'events.db'))
        self.app = m.App.__new__(m.App)
        self.app.db = self.db
        self.app.store = m.EventStore(str(Path(self.temp.name) / 'eve.json'))
        self.app.store.db = self.db
        self.records = []
        # Whole seconds are exactly representable in both the memory and millisecond store.
        stamp = int(m.now()) - 100
        for index, severity in enumerate((1, 2, 3, 4)):
            record = {field: ('Example Évent ' + field) for field in m.SQL_FIELD_COLUMNS}
            record.update({field: 42 for field in m.HUNT_NUMBER_FIELDS})
            record.update(ts=stamp + index, type='alert', sev=severity,
                          level='high' if severity == 1 else 'medium' if severity == 2 else 'low',
                          src='2001:db8::1' if index == 0 else '192.0.2.1', dst='198.51.100.2',
                          ip_version=6 if index == 0 else 4, proto='TCP', app='http',
                          httpver='HTTP/1.1', action='blocked', dir='to_server',
                          sig_id=2021076, flow_id=12345678, sport=443, dport=8443)
            metadata = {'mitre_tactic_id': ['TA0011'], 'mitre_technique_id': ['T1059.001'],
                        'mitre_tactic_name': ['Command and Control'], 'mitre_technique_name': ['PowerShell']}
            if index == 0:
                record.update(metadata)
            raw = dict(timestamp=datetime.datetime.fromtimestamp(record['ts'], datetime.timezone.utc).isoformat(),
                       event_type='alert', src_ip=record['src'], dest_ip=record['dst'],
                       alert=dict(signature='Example', signature_id=2021076, severity=severity,
                                  metadata=metadata if index == 0 else {}))
            self.records.append(record)
            self.db.add(record, json.dumps(raw))
        for index in range(5):
            record = dict(ts=stamp + 10 + index, type='dns', sev=0, level='',
                          src='203.0.113.1', dst='203.0.113.2')
            self.records.append(record)
            self.db.add(record, json.dumps(record))
        self.db.flush()
        self.app.store.events.extend(self.records)
        search = self.db.search_range
        def capped_search(*args, **kwargs):
            kwargs['max_scan'] = 2
            return search(*args, **kwargs)
        self.patch = mock.patch.object(self.db, 'search_range', side_effect=capped_search)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.db.conn.close()
        self.temp.cleanup()

    def check(self, query, icase=False):
        node = m.hunt_parse(query)
        expected = sum(m.hunt_match(node, record, icase) for record in self.records)
        data = self.app.hunt({'q': query, 'all': '1', 'source': 'db', 'icase': '1' if icase else '', 'limit': '500'})
        self.assertFalse(data.get('error'), (query, data.get('error')))
        self.assertEqual(data['total'], expected, query)
        self.assertFalse(data.get('truncated'), query)
        self.assertEqual(len(data['events']), expected, query)

    def test_every_field_spacing_existence_negation_boolean_and_wildcard(self):
        record = self.records[0]
        for name, field in m.HUNT_FIELDS.items():
            value = (m.tuple_hash(record.get('src'),record.get('sport'),record.get('dst'),record.get('dport'),record.get('proto'))
                     if field == 'tuple_hash' and not record.get('community') else record.get(field))
            if value is None:
                self.check(name + ':*')
                self.check('NOT ' + name + ':*')
                continue
            value = value[0] if isinstance(value, list) else value
            for space in ('', ' ', '   ', '\t'):
                term = name + ':' + space + literal(value)
                with self.subTest(field=name, spacing=space):
                    self.check(term)
                    self.check(term, icase=True)
                    self.check('NOT (' + term + ')')
                    self.check(term + ' AND type: alert')
                    self.check(term + ' OR type: dns')
            with self.subTest(field=name, case='exists'):
                self.check(name + ':*')
                self.check(name + ': *')
                self.check('NOT ' + name + ': *')
            if field in m.HUNT_NUMBER_FIELDS:
                for operator in ('', '<', '>', '<=', '>='):
                    with self.subTest(field=name, operator=operator):
                        self.check(name + ': ' + operator + str(value))
            elif field != 'level':
                for pattern in (str(value)[:3] + '*', str(value)[:3] + '?*'):
                    with self.subTest(field=name, pattern=pattern):
                        self.check(name + ': ' + pattern)
                        self.check(name + ': ' + pattern.upper(), icase=True)

    def test_level_presets_aliases_combinations_and_absent_severity(self):
        for value in ('high', 'medium', 'low', 'HIGH', '高危', '中危', '低危', '1', '2', '3', '4', '*', 'unknown'):
            self.check('level: ' + value)
        self.check('level: medium OR level: high')
        self.check('level: medium AND NOT app: dns')
        self.check('NOT level: medium AND type: dns')

    def test_unrated_native_notices_are_searchable_without_inventing_severity(self):
        envelope=dict(engine='snort3',kind='notice',data=dict(ts=m.now()-5,uid=1,gid=129,sid=3,rev=1,msg='native stream warning',action='allow'))
        record,raw=m.EventStore._parse(json.dumps(envelope))
        self.assertEqual(record['sev'],0);self.assertEqual(record['level'],'unknown')
        self.db.add(record,raw);self.db.flush();self.records.append(record)
        for query in ('level: *','level: unknown','level: 未评级','NOT level: *','level:high'):
            self.check(query)

    def test_networks_and_free_text(self):
        for query in ('src: "2001:db8::/64"', 'src: 192.0.2.0/24', 'dst: 198.51.100.0/24',
                      'NOT src: "2001:db8::/64"', 'src: invalid/24',
                      'Example', '*Évent*', 'Évent AND type: alert', 'NOT Example'):
            self.check(query)
            self.check(query, icase=True)

    def test_every_offered_value_matches_stored_evidence(self):
        queries = []
        for name, choices in m.HUNT_VALUE_OPTIONS.items():
            for value, _ in choices:
                record = dict(ts=m.now()-10+len(self.records)/1000, type='alert', sev=0, level='')
                record[m.HUNT_FIELDS[name]] = value
                if name == 'level':
                    record['sev'] = {'high':1,'medium':2,'low':3,'unknown':0}[value]
                    if value=='unknown':record['sig_id']=129
                self.db.add(record,json.dumps(record))
                self.records.append(record)
                queries.append(name+': '+literal(value))
        self.db.flush()
        for query in queries:
            with self.subTest(query=query):
                self.assertTrue(any(m.hunt_match(m.hunt_parse(query), record) for record in self.records))
                self.check(query)

    def test_memory_source_and_empty_database_fallback_keep_the_matcher(self):
        for query in ('level: medium', 'level: unknown', 'level: high OR level: medium',
                      'NOT type: dns', 'sid: 2021076', 'src: 192.0.2.0/24'):
            expected = sum(m.hunt_match(m.hunt_parse(query), record) for record in self.records)
            for source in ('memory', ''):
                with self.subTest(query=query, source=source):
                    data = self.app.hunt({'q': query, 'source': source, 'window': '1440', 'limit': '100'})
                    self.assertEqual(data['total'], expected)

    def test_mixed_case_ipv6_protocol_names(self):
        self.records[0]['proto'] = 'IPv6-ICMP'
        self.db.conn.execute("UPDATE events SET proto='IPv6-ICMP' WHERE sev=1 AND type='alert'")
        self.db.conn.commit()
        for value in ('IPv6-ICMP', 'ipv6-icmp', 'IPV6-ICMP'):
            self.check('proto: ' + value)
            self.check('proto: ' + value, icase=True)

    def test_mixed_case_application_and_http_version(self):
        for field, value in (('app', 'HTTP'), ('httpver', 'http/1.1')):
            self.records[0][field] = value
            self.db.conn.execute('UPDATE events SET ' + field + '=? WHERE sev=1 AND type=\'alert\'', (value,))
            self.db.conn.commit()
            self.check(field + ': ' + value.upper())
            self.check(field + ': ' + value.lower())

    def test_fractional_flow_timestamps_remain_sql_filtered(self):
        for field in ('flow_start','flow_end'):
            self.records[0][field] = 1700000000.125
            self.db.conn.execute('UPDATE events SET '+field+'=? WHERE sev=1 AND type=\'alert\'',(1700000000.125,))
            self.db.conn.commit()
            for value in ('1700000000.125','>=1700000000.1','<1700000000.2','1.700000000125e9','{* TO -1}'):
                query=field+': '+value
                with self.subTest(query=query):
                    self.assertTrue(m.hunt_sql_pushdown(m.hunt_parse(query))[2])
                    self.check(query)

    def test_large_integer_flow_ids_do_not_match_an_adjacent_id(self):
        self.records[0]['flow_id'] = 9007199254740993
        self.db.conn.execute('UPDATE events SET flow_id=? WHERE sev=1 AND type=\'alert\'',(9007199254740993,))
        self.db.conn.commit()
        self.check('flow:9007199254740993')
        self.check('flow:9007199254740992')
        self.assertTrue(m.hunt_match(m.hunt_parse('flow:9007199254740993'),self.records[0]))
        self.assertFalse(m.hunt_match(m.hunt_parse('flow:9007199254740992'),self.records[0]))

    def test_file_source_receives_the_original_predicate(self):
        def history(window, matcher, limit, offset):
            records = [record for record in self.records if matcher(record)]
            return len(records), records[offset:offset + limit]
        with mock.patch.object(self.app.store, 'search_history', side_effect=history):
            for query in ('level: medium', 'level: unknown', 'sid: 2021076', 'NOT type: dns'):
                expected = sum(m.hunt_match(m.hunt_parse(query), record) for record in self.records)
                data = self.app.hunt({'q': query, 'source': 'file', 'window': '1440', 'limit': '100'})
                self.assertEqual(data['total'], expected)


if __name__ == '__main__':
    unittest.main()
