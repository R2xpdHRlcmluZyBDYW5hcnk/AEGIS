#!/usr/bin/env python3
"""ips-web 回归测试：密码兼容、CSV 导出、请求体限制与登录集成。"""

import hashlib
import json
import re
import io
import sqlite3
import http.client
import importlib.machinery
import importlib.util
import shutil
import shlex
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOADER = importlib.machinery.SourceFileLoader("ips_web_under_test", str(ROOT / "ips-web"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
ips_web = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(ips_web)


class FakeSessions:
    def __init__(self):
        self.ttl = 43200

    def get(self, token):
        return {"user": "admin"} if token == "test-token" else None

    def create(self, user, client):
        self.last_user = user
        self.last_client = client
        return "test-token"

    def drop(self, token):
        self.dropped = token


class FakeApp:
    def __init__(self, events=None):
        self.sessions = FakeSessions()
        self.events_payload = events or []
        self.failures = 0

    def login_throttled(self, ip):
        return False

    def note_login_failure(self, ip):
        self.failures += 1

    def clear_login_failures(self, ip):
        self.failures = 0

    def events(self, params):
        self.last_event_params = dict(params)
        return {"total": len(self.events_payload), "events": self.events_payload}


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ips_web.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host, cls.port = cls.server.server_address

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.app = FakeApp([
            {
                "ts": 1761794400.0,
                "type": "alert",
                "sev": 2,
                "sig_id": 2100498,
                "sig": "=cmd|' /C calc'!A1",
                "src": "192.0.2.10",
                "sport": 51000,
                "dst": "198.51.100.20",
                "dport": 443,
                "proto": "TCP",
                "action": "blocked",
            }
        ])
        ips_web.Handler.app = self.app
        ips_web.Handler.config = {}

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        result_headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        conn.close()
        return status, result_headers, data

    def auth_headers(self):
        return {"Cookie": "ipsweb_session=test-token"}

    def test_log_page_and_stream_filters_still_require_a_session(self):
        for path in ('/api/overview?missing_app=1', '/api/hunt?from=100&to=200&offset=50',
                     '/api/stream?topic=overview&missing_app=1'):
            for headers in ({}, {'Cookie':'ipsweb_session=invalid-token'}):
                with self.subTest(path=path, headers=headers):
                    status, _, data = self.request('GET', path, headers=headers)
                    self.assertEqual(status, 401)
                    self.assertIn('error', json.loads(data))

    def test_create_actions_reject_duplicates_but_explicit_edit_updates_once(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {key: str(Path(directory) / key) for key in
                     ('DROP_CONF','MODIFY_CONF','ACTION_CONF','DISABLE_CONF','THRESHOLD_CONF','SUPPRESS_LUA')}
            for path in paths.values(): Path(path).write_text('')
            with mock.patch.multiple(ips_web, **paths):
                headers = dict(self.auth_headers(), **{'X-Requested-With':'ips-web','Content-Type':'application/json'})
                post = lambda path, data: json.loads(self.request('POST', path, json.dumps(data), headers)[2])
                self.assertTrue(post('/api/rules/action', {'action':'drop','selectors':['sid:00123']})['ok'])
                duplicate = post('/api/rules/action', {'action':'reject','selectors':['sid:123']})
                self.assertFalse(duplicate['ok'])
                self.assertEqual(ips_web.governance_state()['action'], [{'action':'drop','selector':'sid:123'}])
                self.assertTrue(post('/api/rules/action', {'action':'reject','selectors':['sid:123'],'replace':True})['ok'])
                self.assertEqual(len(ips_web.governance_state()['action']), 1)
                self.assertFalse(post('/api/rules/reject', {'values':['sid:123'],'replace':True})['ok'])
                self.assertTrue(post('/api/rules/reject', {'values':['group:emerging-*']})['ok'])
                self.assertFalse(post('/api/rules/reject', {'values':['group:emerging-scan']})['ok'])
                self.assertFalse(post('/api/rules/reject', {'values':['group:emerging-scan'],'replace':True})['ok'])
                self.assertEqual(len(ips_web.governance_state()['drop']), 1)
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: post('/api/rules/action', {'action':'drop','selectors':['sid:124']}), range(2)))
                self.assertEqual(sum(r['ok'] for r in results), 1)
                self.assertEqual(len(ips_web.governance_state()['action']), 2)

    def test_cached_apply_endpoint_is_separate_from_online_update(self):
        self.app.sys = mock.Mock()
        self.app.sys.update_rules.return_value = {'ok':True}
        headers = dict(self.auth_headers(), **{'X-Requested-With':'ips-web','Content-Type':'application/json'})
        self.assertTrue(json.loads(self.request('POST','/api/actions/apply','{}',headers)[2])['ok'])
        self.app.sys.update_rules.assert_called_once_with(offline=True)
        self.app.sys.update_rules.reset_mock()
        self.assertTrue(json.loads(self.request('POST','/api/actions/update','{}',headers)[2])['ok'])
        self.app.sys.update_rules.assert_called_once_with()

    def test_group_suppression_persists_policy_and_renders_more_than_200_members(self):
        from concurrent.futures import ThreadPoolExecutor
        rows = [{'name':'large','label':'Large','source':'active','source_enabled':True},
                {'name':'overlap','label':'Overlap','source':'active','source_enabled':True},
                {'name':'stopped','label':'Stopped','source':'old','source_enabled':False}]
        cache = {'members':{('large','active'):set(range(1,352)), ('overlap','active'):set(range(300,401)),
                            ('stopped','old'):{999}}, 'names':{}, 'actions':{}}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'threshold.config'
            original = '# keep\nthreshold gen_id 1, sig_id 2, type limit, track by_src, count 1, seconds 60\nsuppress gen_id 1, sig_id 1\n'
            target.write_text(original)
            self.app.sys = mock.Mock()
            with mock.patch.object(ips_web, 'rule_group_catalog', return_value=rows), \
                 mock.patch.object(ips_web, '_GROUP_CACHE', cache), mock.patch.object(ips_web, 'THRESHOLD_CONF', str(target)), mock.patch.object(ips_web,'SUPPRESS_LUA',str(Path(directory)/'suppress.lua')), \
                 mock.patch.object(ips_web, 'active_rule_ids', return_value=None):
                headers = dict(self.auth_headers(), **{'X-Requested-With':'ips-web','Content-Type':'application/json'})
                post = lambda data: json.loads(self.request('POST','/api/rules/suppress-groups',json.dumps(data),headers)[2])
                self.assertFalse(post({'groups':['large','missing']})['ok'])
                self.assertFalse(post({'groups':['stopped']})['ok'])
                self.assertEqual(target.read_text(), original)
                available = ips_web.suppression_group_catalog()
                self.assertEqual(next(row for row in available if row['name']=='large')['available'],351)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _:post({'groups':['large','overlap'], 'sids':['0400','401']}), range(2)))
                self.assertTrue(all(result['ok'] for result in results))
                self.assertEqual(sum(result['added'] for result in results),2)
                self.assertEqual(sum(result['added_groups'] for result in results),2)
                self.app.sys.reload_rules.assert_called_once_with()
                content = target.read_text()
                self.assertTrue(content.startswith(original))
                self.assertEqual(content.count('suppress gen_id 1, sig_id '),3)
                self.assertEqual(Path(ips_web.SUPPRESS_LUA).read_text().count('gid = 1, sid = '),401)
                configured_groups = ips_web.suppression_group_catalog()
                self.assertEqual(configured_groups,[])
                self.assertFalse(post({'groups':['large'], 'sids':['0']})['ok'])
                with mock.patch.object(ips_web.os, 'replace', side_effect=OSError('fixture write failure')):
                    with self.assertRaises(OSError):
                        ips_web.suppress_groups_add(['large'], ['402'])
                self.assertEqual(target.read_text(),content)
                self.assertFalse(Path(str(target)+'.ips-web-tmp').exists())

    def test_password_hash_formats(self):
        password = "correct horse battery staple"
        encoded = ips_web.make_password_hash(password, iterations=10000)
        config = {"password_pbkdf2": encoded}
        self.assertTrue(ips_web.verify_password(password, config))
        self.assertFalse(ips_web.verify_password(password + "!", config))
        self.assertFalse(ips_web.verify_password(password, {"password_pbkdf2": "pbkdf2-sha256$9$a$"}))
        self.assertTrue(ips_web.password_configured(config))

        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        legacy_config = {"password_sha256": legacy.upper()}
        self.assertTrue(ips_web.verify_password(password, legacy_config))
        self.assertFalse(ips_web.verify_password("wrong", legacy_config))
        self.assertTrue(ips_web.password_configured(legacy_config))
        self.assertFalse(ips_web.password_configured({}))

    def test_csv_formula_injection_guard(self):
        text = ips_web.events_csv([
            {"ts": 1761794400, "type": "alert", "sev": 2, "sig_id": 1,
             "sig": "=1+1", "src": "+192.0.2.1", "dst": "-192.0.2.2"}
        ])
        self.assertTrue(text.startswith("\ufeff"))
        lines = text.lstrip("\ufeff").splitlines()
        self.assertEqual(lines[0], "time,type,severity,sid,signature,source,source_port,destination,destination_port,protocol,action")
        self.assertIn("'=1+1", lines[1])
        self.assertIn("'+192.0.2.1", lines[1])
        self.assertIn("'-192.0.2.2", lines[1])

    def test_csv_endpoint_requires_session_and_sets_headers(self):
        status, headers, body = self.request(
            "GET", "/api/events?type=alert&format=csv", headers=self.auth_headers())
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["content-type"])
        self.assertIn("attachment", headers["content-disposition"])
        self.assertEqual(headers["content-security-policy"], "default-src 'none'")
        self.assertTrue(body.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"'=cmd|' /C calc'!A1", body)

        status, headers, body = self.request("GET", "/api/events?format=csv")
        self.assertEqual(status, 401)

    def test_pbkdf2_login_and_secure_cookie(self):
        password = "test-password"
        ips_web.Handler.config = {
            "user": "admin",
            "password_pbkdf2": ips_web.make_password_hash(password, iterations=10000),
            "secure_cookie": True,
        }
        form = urllib.parse.urlencode({"username": "admin", "password": password, "next": "/"})
        status, headers, _ = self.request(
            "POST", "/login", body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302)
        self.assertIn("ipsweb_session=test-token", headers.get("set-cookie", ""))
        self.assertIn("Secure", headers.get("set-cookie", ""))
        self.assertEqual(self.app.sessions.last_user, "admin")

    def test_login_page_has_favicon_and_hides_hostname(self):
        ips_web.Handler.config = {"user": "admin", "password_sha256": "x" * 64}
        with mock.patch.object(ips_web.socket, 'gethostname', return_value='sensor.example.test'):
            status, _, body = self.request('GET', '/login')
        self.assertEqual(status, 200)
        self.assertIn('<img class="brand-icon" src="/favicon.svg" alt="">', body.decode('utf-8'))
        self.assertNotIn('<h1', body.decode('utf-8'))
        self.assertNotIn('sensor.example.test', body.decode('utf-8'))

    def test_login_neutral_palette_matches_console(self):
        ips_web.Handler.config = {'user': 'admin', 'password_sha256': 'x' * 64}
        status, _, body = self.request('GET', '/login')
        self.assertEqual(status, 200)
        html = body.decode('utf-8')
        css = (ROOT / 'frontend/src/styles.css').read_text(encoding='utf-8')
        for name in ('bg', 'surface', 'line', 'muted', 'text'):
            pattern = r'--' + name + r':(#[0-9a-f]+)'
            self.assertEqual(re.search(pattern, html).group(1), re.search(pattern, css).group(1))
        self.assertIn('background:#477a4b', html)
        self.assertIn('border:1px solid #8d5151;background:#432c2c', html)

    def test_legacy_sha256_login_still_works(self):
        password = "legacy-password"
        ips_web.Handler.config = {
            "user": "admin",
            "password_sha256": hashlib.sha256(password.encode("utf-8")).hexdigest(),
        }
        form = urllib.parse.urlencode({"username": "admin", "password": password, "next": "/"})
        status, headers, _ = self.request(
            "POST", "/login", body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302)
        self.assertIn("ipsweb_session=test-token", headers.get("set-cookie", ""))

    def test_api_rejects_non_object_json_and_read_body_limit(self):
        headers = dict(self.auth_headers())
        headers.update({
            "Content-Type": "application/json",
            "X-Requested-With": "ips-web",
        })
        status, _, body = self.request("POST", "/api/not-found", body=b"[1,2,3]", headers=headers)
        self.assertEqual(status, 400)
        self.assertIn(b"object", body)

        # 超限时不继续读取主体并关闭连接；若让客户端先发超大正文，Windows 本地测试会偶发连接中止。
        handler = object.__new__(ips_web.Handler)
        handler.headers = {"Content-Length": str(ips_web.API_BODY_LIMIT + 1)}
        handler.close_connection = False
        errors = []
        handler._error = lambda status, message: errors.append((status, message)) or None
        self.assertIsNone(handler._read_body(ips_web.API_BODY_LIMIT))
        self.assertEqual(errors, [(413, "request body too large")])
        self.assertTrue(handler.close_connection)


class HuntSyntaxCase(unittest.TestCase):
    def test_spacing_after_field_colons_preserves_all_supported_examples(self):
        for field in ips_web.App.hunt_schema()['fields']:
            name, _, value = field['example'].partition(':')
            expected = ips_web.hunt_parse(field['example'])
            for spacing in ('', ' ', '   ', '\t'):
                with self.subTest(field=name, spacing=spacing):
                    self.assertEqual(ips_web.hunt_parse(name + ':' + spacing + value), expected)
        self.assertEqual(ips_web.hunt_parse('src:"2001:db8::1" AND url:"https://example.test/a:b"'),
                         ips_web.hunt_parse('src: "2001:db8::1" AND url: "https://example.test/a:b"'))

    def test_query_fields_use_record_names_for_database_and_numeric_filters(self):
        self.assertEqual(set(ips_web.HUNT_FIELDS.values()) - ips_web.DB_COLUMN_FIELDS,
                         set(ips_web.MITRE_FIELDS))
        for query in ('sid:2021076', 'sid: 2021076', 'sid: >=2021000'):
            node = ips_web.hunt_parse(query)
            self.assertTrue(ips_web.hunt_match(node, {'sig_id': 2021076}))
            self.assertFalse(ips_web.hunt_match(node, {'sig_id': 2000000}))
            self.assertFalse(ips_web.hunt_match(node, {}))
            _, _, full = ips_web.hunt_sql_pushdown(node)
            self.assertTrue(full)
        for query in ('sid:*', 'sid: *'):
            node = ips_web.hunt_parse(query)
            self.assertTrue(ips_web.hunt_match(node, {'sig_id': 2021076}))
            self.assertFalse(ips_web.hunt_match(node, {'sig_id': None}))
            _, _, full = ips_web.hunt_sql_pushdown(node)
            self.assertTrue(full)

    def test_sev_field_removed(self):
        with self.assertRaises(ips_web.HuntError):
            ips_web.hunt_parse("sev:<3")
        with self.assertRaises(ips_web.HuntError):
            ips_web.hunt_parse("sev:2")

    def test_level_never_matches_missing_severity(self):
        node = ips_web.hunt_parse("level:high")
        self.assertFalse(ips_web.hunt_match(node, {"level": ""}))
        self.assertTrue(ips_web.hunt_match(node, {"level": "high"}))
        alias = ips_web.hunt_parse("level:2")
        self.assertTrue(ips_web.hunt_match(alias, {"level": "medium"}))

    def test_numeric_pushdown_still_works(self):
        where, args, full = ips_web.hunt_sql_pushdown(ips_web.hunt_parse("sport:<1024"))
        self.assertTrue(full)
        self.assertEqual(where, ["sport < ?"])
        self.assertEqual(args, [1024])

    def test_ip_version_hunt_field(self):
        node = ips_web.hunt_parse("ip_version:6")
        self.assertTrue(ips_web.hunt_match(node, {"ip_version": 6}))
        self.assertFalse(ips_web.hunt_match(node, {"ip_version": 4}))
        where, args, full = ips_web.hunt_sql_pushdown(node)
        self.assertTrue(full)
        self.assertEqual(where, ["ip_version = ?"])
        self.assertEqual(args, [6])

    def test_wildcard_star_means_field_exists(self):
        star = ips_web.hunt_parse("level:*")
        self.assertTrue(ips_web.hunt_match(star, {"level": "high"}))
        self.assertFalse(ips_web.hunt_match(star, {"level": ""}))
        self.assertFalse(ips_web.hunt_match(star, {}))
        sport = ips_web.hunt_parse("sport:*")
        self.assertTrue(ips_web.hunt_match(sport, {"sport": 51000}))
        self.assertFalse(ips_web.hunt_match(sport, {"sport": None}))
        sni = ips_web.hunt_parse("sni:*")
        self.assertTrue(ips_web.hunt_match(sni, {"sni": "a"}))
        self.assertFalse(ips_web.hunt_match(sni, {"sni": ""}))
        _, _, full = ips_web.hunt_sql_pushdown(star)
        self.assertTrue(full)


class SeriesCase(unittest.TestCase):
    """总览趋势：内存覆盖不到的区间从事件库补齐，两边不重复计数。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = ips_web.EventDB(str(self.tmp / "events.db"))
        self.store = ips_web.EventStore(str(self.tmp / "eve.json"))
        self.store.db = self.db

    def tearDown(self):
        self.db.conn.close()
        shutil.rmtree(self.tmp)

    def _db_insert(self, ts, etype):
        self.db.add({"ts": ts, "type": etype}, '{"event_type":"%s"}' % etype)
        self.db.flush()

    def test_series_backfills_from_db_without_double_count(self):
        now_min = int(ips_web.now() // 60) * 60
        self._db_insert(now_min - 10 * 3600, "alert")   # 仅事件库（模拟重启前已写入）
        self._db_insert(now_min - 5 * 3600, "drop")
        self.store.buckets[now_min - 2 * 60] = [3, 1]   # 仅内存（模拟事件库批量写入延迟）
        self._db_insert(now_min - 60, "alert")          # 两边都有：以内存为准，不叠加
        self.store.buckets[now_min - 60] = [1, 0]
        points = self.store.series(1440, 60)
        self.assertEqual(len(points), 24)
        self.assertTrue(all(p["t"] % 3600 == 0 for p in points))
        self.assertEqual(sum(p["alerts"] for p in points), 5)   # 重复计数会变成 6
        self.assertEqual(sum(p["drops"] for p in points), 2)
        by_hour = {p["t"] // 3600: p for p in points}
        self.assertEqual(by_hour[(now_min - 10 * 3600) // 3600]["alerts"], 1)
        self.assertEqual(by_hour[(now_min - 5 * 3600) // 3600]["drops"], 1)

    def test_search_exposes_scan_limit_and_resets_on_next_query(self):
        current = ips_web.now()
        for index in range(3):
            self._db_insert(current - index, "alert")
        total, rows = self.db.search_range(current - 10, current + 1,
                                           matcher=lambda event: True, max_scan=2)
        self.assertEqual(total, 2)
        self.assertEqual(len(rows), 2)
        self.assertTrue(self.db.last_truncated)
        total, _ = self.db.search_range(current - 10, current + 1,
                                        matcher=lambda event: True, max_scan=10)
        self.assertEqual(total, 3)
        self.assertFalse(self.db.last_truncated)


class NDRRegressionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.db = ips_web.EventDB(str(self.path / 'events.db'))
        self.store = ips_web.EventStore(str(self.path / 'eve.json'), initial_tail=64)
        self.store.db = self.db
        self.app = ips_web.App.__new__(ips_web.App)
        self.app.db, self.app.store = self.db, self.store
        self.app.network = ips_web.NetworkSnapshots(self.db)

    def tearDown(self):
        self.app.network.close()
        self.db.conn.close()
        self.tmp.cleanup()

    def add(self, etype='alert', **fields):
        rec = dict(ts=ips_web.now() - 10, type=etype, sev=1, src='192.0.2.7',
                   dst='198.51.100.4', sport=43210, dport=443, proto='TCP',
                   sig='Example alert', sig_id=42, action='allowed', cat='Test', app='tls')
        rec.update(fields)
        if rec.get('flow_id') and 'community' not in fields:
            rec['community']='fixture:'+str(rec['flow_id'])
        if rec.get('flow_id') and 'session_id' not in fields:
            rec['session_id']=self.session(rec['flow_id'])
        self.db.add(rec, json.dumps(rec))
        self.db.flush()
        return rec

    @staticmethod
    def session(number):
        return 'c'*32+':'+format(number,'016x')

    def test_timezone_variants_without_fraction(self):
        utc = ips_web.parse_ts('2026-10-30T01:02:03Z')
        self.assertEqual(utc, ips_web.parse_ts('2026-10-30T09:02:03+0800'))
        self.assertEqual(utc, ips_web.parse_ts('2026-10-30T09:02:03+08:00'))
        self.assertAlmostEqual(ips_web.parse_ts('2026-10-30T09:02:03.123456+0800') - utc, .123456, places=6)

    def test_timeout_logging_before_request_line_is_safe(self):
        handler = ips_web.Handler.__new__(ips_web.Handler)
        handler.address_string = lambda: '127.0.0.1'
        with mock.patch.object(ips_web.sys, 'stderr', io.StringIO()) as output:
            handler.log_message('Request timed out: %s', 'idle connection')
            self.assertIn('idle connection', output.getvalue())

    def test_event_filters_use_database_fields_and_ports(self):
        self.add()
        self.add(sev=2, sig_id=43, sig='Other', proto='UDP')
        result = self.app.events({'type': 'alert', 'sev': '1', 'proto': 'tcp', 'q': '443'})
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['events'][0]['sig_id'], 42)
        self.assertEqual(self.app.events({'q': '198.51.100.4', 'action': 'allowed'})['total'], 2)
        self.assertEqual(self.app.events({'q': "%' OR 1=1 --"})['total'], 0)

    def test_relative_window_survives_empty_memory(self):
        self.add(ts=ips_web.now() - 7200)
        self.assertEqual(len(self.store.events), 0)
        self.assertEqual(self.app.events({'window': '360'})['total'], 1)
        self.assertEqual(self.app.events({'window': '60'})['total'], 0)

    def test_security_summary_excludes_protocol_telemetry(self):
        self.add()
        self.add('drop', action='blocked', sev=0, reason='stream', sig_id=None)
        self.add('dns', src='203.0.113.99', sig='Ordinary DNS')
        summary = self.db.security_summary()
        self.assertEqual((summary['alerts'], summary['high'], summary['drops'], summary['total']), (1, 1, 1, 2))
        self.assertEqual(summary['sources_count'], 1)
        self.assertNotIn('Ordinary DNS', [item['sig'] for item in summary['signatures']])
        self.assertEqual(self.app.aggregate({'type': 'drop'})['total'], 1)

    def test_overview_merges_matching_alert_and_drop_only(self):
        stamp = ips_web.now() - 10
        signature = 'GPL ATTACK_RESPONSE id check returned root'
        common = dict(ts=stamp, sev=2, sig=signature, sig_id=2100498, flow_id=123456, tx=8,
                      action='blocked')
        self.add(**common)
        self.add('drop', **dict(common, sev=0))
        self.add(ts=stamp + .001, sev=2, sig=signature, sig_id=2100498, flow_id=123456, tx=8)

        summary = self.db.security_summary(dedup=True)
        self.assertEqual((summary['total'], summary['alerts'], summary['drops']), (2, 2, 1))
        self.assertEqual(summary['signatures'][0]['count'], 2)
        self.assertEqual(summary['signatures'][0]['sev'], 2)
        points = self.db.security_series(60, 1)
        self.assertEqual(sum(point['alerts'] for point in points), 2)
        self.assertEqual(sum(point['drops'] for point in points), 1)
        total, recent = self.db.search_range(stamp - 1, stamp + 1, types=['alert', 'drop'], dedup=True)
        self.assertEqual(total, 2)
        blocked = next(event for event in recent if event['action'] == 'blocked')
        self.assertEqual((blocked['type'], blocked['sev'], blocked['action']), ('alert', 2, 'blocked'))
        self.assertEqual(self.app.events({'window': '60'})['total'], 3)

    def test_overview_never_merges_alert_records(self):
        stamp = ips_web.now() - 10
        common = dict(ts=stamp, sport=None, dport=None, proto='IPv6-ICMP', flow_id=842076)
        self.add(**common)
        self.add(**dict(common, cat='Independent decoder alert'))

        summary = self.db.security_summary(dedup=True)
        self.assertEqual((summary['total'], summary['alerts']), (2, 2))
        total, recent = self.db.search_range(stamp - 1, stamp + 1, types=['alert', 'drop'], dedup=True)
        self.assertEqual((total, len(recent)), (2, 2))
        self.assertEqual(sum(point['alerts'] for point in self.db.security_series(60, 1)), 2)

    def test_reject_only_detections_count_without_manufacturing_alert_rows(self):
        stamp = int(ips_web.now())
        self.add('drop', ts=stamp-10, sig_id=498, sev=2, action='blocked')
        self.add('drop', ts=stamp-9, sig_id=499, sev=1, action='blocked')
        self.add('drop', ts=stamp-8, sig_id=500, sev=0, action='blocked')
        self.add('drop', ts=stamp-7, sig_id=None, sev=0, sig='engine drop', action='blocked')
        self.add('drop', ts=stamp-901, sig_id=501, sev=1, action='blocked')
        summary = self.db.security_summary(start=stamp-900, end=stamp, dedup=True)
        self.assertEqual((summary['total'], summary['alerts'], summary['high'], summary['drops']), (4, 3, 1, 4))
        series = self.db.security_series(15, 1, start=stamp-900, end=stamp)
        self.assertEqual((sum(p['alerts'] for p in series), sum(p['drops'] for p in series)), (3, 4))
        self.assertEqual(self.db.conn.execute("SELECT COUNT(*) FROM events WHERE type='alert'").fetchone()[0], 0)

    def test_overview_filters_apply_to_summary_trend_recent_and_network(self):
        self.app.sys = mock.Mock()
        for method in ('service', 'counters', 'ruleset', 'queue', 'current_rates', 'reload_state'):
            getattr(self.app.sys, method).return_value = {}
        self.add('drop', sig_id=498, action='blocked', sev=2)
        self.add(sig_id=499, sev=1)
        self.add('flow', sig_id=None, src='203.0.113.6', app='http')
        self.app.network.start()
        result = self.app.overview({'window':'15', 'detection':'alerts', 'sid':'498'})
        self.assertEqual((result['security']['alerts'],result['security']['drops']), (1, 1))
        self.assertEqual(sum(p['alerts'] for p in result['series']), 1)
        self.assertEqual([row['sig_id'] for row in result['recent']], [498])
        changed = self.app.overview({'window':'15', 'detection':'high'})
        self.assertEqual((changed['security']['alerts'],changed['security']['high']), (1, 1))
        push = self.app._overview_push({'src':'203.0.113.6', 'type':'flow', 'app':'http'})
        network = self.db.compute_network_summary(self.db.conn, ips_web.now()-900, ips_web.now(), push=push)
        self.assertEqual((network['flows'],network['dns'],network['addresses']), (1,0,2))
        self.assertEqual(network['applications'],[{'name':'http','count':1}])
        empty = self.app.overview({'window':'15','sig':"' OR 1=1 --"})
        self.assertEqual(empty['security']['total'],0)
        self.assertEqual(empty['recent'],[])
        stamp = ips_web.now()
        for index in range(14):
            self.add('flow', ts=stamp-60+index, sport=43000+index, proto='UDP', app='')
        recent = self.app.overview({'window':'15','proto':'UDP','missing_app':'1'})['recent']
        self.assertEqual([row['sport'] for row in recent], list(range(43013,43003,-1)))
        for invalid in ({'detection':'anything'},{'sid':'nan'},{'sid':'-1'},{'sid':'4294967296'},
                        {'type':'nonsense'},{'src':[]},{'sig':'x'*1025}):
            with self.assertRaises(ValueError):self.app.overview(invalid)

    def test_overview_uses_one_interval_for_summary_trend_and_recent(self):
        self.app.sys = mock.Mock()
        self.app.sys.service.return_value = {}
        self.app.sys.counters.return_value = {}
        self.app.sys.ruleset.return_value = {}
        self.app.sys.queue.return_value = {}
        self.app.sys.current_rates.return_value = {}
        self.app.sys.reload_state.return_value = {}
        high = ips_web.now() - 86400
        low = high - 3600
        self.add(ts=low + 600, sig='In selected interval')
        self.add(ts=low - 1, sig='Before selected interval')
        self.add(ts=high + 1, sig='After selected interval')
        result = self.app.overview({'from': str(low), 'to': str(high)})
        self.assertEqual(result['range'], [low, high])
        self.assertEqual(result['security']['alerts'], 1)
        self.assertEqual(sum(point['alerts'] for point in result['series']), 1)
        self.assertEqual([event['sig'] for event in result['recent']], ['In selected interval'])
        self.assertEqual(result['window'], 60)

    def test_overview_defaults_to_24_hours_and_supports_30_days(self):
        self.app.sys = mock.Mock()
        for method in ('service', 'counters', 'ruleset', 'queue', 'current_rates', 'reload_state'):
            getattr(self.app.sys, method).return_value = {}
        self.add(ts=ips_web.now() - 12 * 3600, sig='Within one day')
        self.add(ts=ips_web.now() - 20 * 86400, sig='Within thirty days')
        default = self.app.overview()
        self.assertEqual(default['security']['alerts'], 1)
        self.assertEqual(default['window'], 1440)
        self.assertEqual(self.app.overview({'window': '43200'})['security']['alerts'], 2)
        for params in ({'from': 'nan'}, {'from': '100', 'to': '50'}):
            with self.assertRaises(ValueError):
                self.app.overview(params)

    def test_security_incidents_group_flows_and_expose_related_evidence(self):
        stamp = int(ips_web.now()) - 100
        self.add(ts=stamp - 20, sev=3, sig='First signature', sig_id=101, flow_id=777)
        self.add(ts=stamp - 10, sev=1, sig='Second signature', sig_id=102, flow_id=777,
                 action='blocked')
        self.add(ts=stamp - 5, sev=2, sig='Other flow', sig_id=103, flow_id=778)
        self.add(ts=stamp, sev=2, sig='No flow A', sig_id=104, flow_id=None, sport=None)
        self.add(ts=stamp, sev=2, sig='No flow B', sig_id=105, flow_id=None, sport=None)
        self.add('drop', ts=stamp - 10, sev=1, sig='Second signature', sig_id=102,
                 flow_id=777, action='blocked')
        self.add('drop', ts=stamp - 5, sev=2, sig='Other flow', sig_id=103,
                 flow_id=778, action='blocked')
        self.add('dns', ts=stamp - 9, sig='DNS example.org', sig_id=None, flow_id=777)
        self.add('dns', ts=stamp + 1000, sig='Outside context', sig_id=None, flow_id=777)

        total, incidents = self.db.security_incidents(stamp - 60, stamp + 60)
        self.assertEqual(total, 4)
        self.assertEqual(len(incidents), 4)
        incident = next(item for item in incidents if item['id'] == 'session:'+self.session(777))
        self.assertEqual((incident['alert_count'], incident['signature_count']), (2, 2))
        self.assertEqual((incident['sev'], incident['action']), (1, 'blocked'))
        self.assertEqual(next(item for item in incidents if item['id'] == 'session:'+self.session(778))['action'], 'blocked')
        self.assertEqual(len(incident['signatures']), 2)
        detail = self.db.security_incident('session:'+self.session(777), stamp - 60, stamp + 60)
        self.assertEqual(detail['relation'], 'session')
        self.assertEqual(len(detail['alerts']), 2)
        self.assertEqual(detail['incident']['network_count'], 5)
        self.assertEqual(len(detail['network']), 5)
        self.assertEqual({e['type'] for e in detail['network']}, {'alert', 'drop', 'dns'})
        self.assertTrue(all(e['flow_id'] == 777 for e in detail['network']))
        fallback = next(item for item in incidents if item['id'].startswith('event:'))
        self.assertEqual(self.db.security_incident(fallback['id'], stamp - 60, stamp + 60)['relation'], 'event')
        filtered = self.app.incidents({'from': str(stamp - 60), 'to': str(stamp + 60),
                                       'sev': '1', 'q': 'Second'})
        self.assertEqual(filtered['total'], 1)
        self.assertEqual(self.app.events({'type': 'alert', 'from': str(stamp - 60),
                                          'to': str(stamp + 60)})['total'], 5)
        with self.assertRaises(ValueError):
            self.app.incident({'id': 'flow:invalid'})

    def test_entire_flow_history_and_network_pagination(self):
        stamp = int(ips_web.now()) - 10
        self.add(ts=stamp, flow_id=999, sig_id=100)
        self.add(ts=stamp - 86400, flow_id=999, sig_id=101)
        for index in range(121):
            self.add('tls', ts=stamp - 7200 - index, flow_id=999, sig_id=None, sig='whole-flow-%d' % index)
        self.add('tls', ts=stamp - 7200, flow_id=998, sig_id=None, sig='unrelated')
        first = self.app.incident({'id': 'session:'+self.session(999), 'from': str(stamp - 60), 'to': str(stamp + 1)})
        self.assertEqual(first['incident']['alert_count'], 2)
        self.assertEqual(first['incident']['network_count'], 123)
        self.assertEqual(len(first['network']), 50)
        self.assertFalse(first['truncated'])
        second = self.app.incident({'id': 'session:'+self.session(999), 'from': str(stamp - 60), 'to': str(stamp + 1), 'network_offset': '50'})
        third = self.app.incident({'id': 'session:'+self.session(999), 'from': str(stamp - 60), 'to': str(stamp + 1), 'network_offset': '100'})
        records = first['network'] + second['network'] + third['network']
        self.assertEqual(len(records), 123)
        self.assertEqual(len({r['ts'] for r in records}), 123)
        self.assertTrue(all(r['flow_id'] == 999 for r in records))
        hunted = self.app.hunt({'q': 'session_id:'+json.dumps(self.session(999)), 'all': '1', 'limit': '500', 'from': str(stamp - 1), 'to': str(stamp + 1)})
        self.assertEqual(hunted['total'], 123)
        self.assertEqual(hunted['source'], 'db')

    def test_flow_pushdown_and_alert_drop_only_timeline(self):
        stamp = int(ips_web.now()) - 10
        self.add(ts=stamp, flow_id=144611493630868)
        self.add('drop', ts=stamp + 1, flow_id=144611493630868, sig_id=None)
        self.add('drop', ts=stamp + 2, flow_id=144611493630868)
        detail = self.db.security_incident('session:'+self.session(144611493630868), stamp - 1, stamp + 3)
        self.assertEqual(detail['incident']['network_count'], 3)
        self.assertEqual({r['type'] for r in detail['network']}, {'alert', 'drop'})
        push, args, full = ips_web.hunt_sql_pushdown(ips_web.hunt_parse('flow:144611493630868'))
        self.assertTrue(full)
        count, _ = self.db.search_range(0, ips_web.now(), push=(push, args), max_scan=1)
        self.assertEqual(count, 3)
        self.assertFalse(self.db.last_truncated)

    def test_linked_flow_bounds_round_outward_to_minutes(self):
        start = (int(ips_web.now()) // 60 - 10) * 60
        self.add(ts=start + 3 * 60 + 1.5, flow_id=123)
        self.add('dns', ts=start + 1.25, flow_id=123, sig_id=None)
        self.add(ts=start - 3600, flow_id=124)
        bounds = self.app.hunt_flow_range({'flow': '123'})
        self.assertEqual(bounds, {'from': start, 'to': start + 4 * 60})
        result = self.app.hunt({'q': 'flow: 123', 'from': str(bounds['from']), 'to': str(bounds['to']), 'source': 'db'})
        self.assertEqual(result['total'], 2)
        self.add(ts=start, flow_id=125)
        self.assertEqual(self.app.hunt_flow_range({'flow': '125'}), {'from': start, 'to': start})
        self.assertIn('error', self.app.hunt_flow_range({'flow': '999'}))
        for value in ('0', '-1', 'bad', '9223372036854775808'):
            with self.assertRaises(ValueError):
                self.app.hunt_flow_range({'flow': value})

    def test_scan_limit_state_is_isolated_between_threads(self):
        self.db.last_truncated = True
        states = []
        def other_request():
            states.append(self.db.last_truncated)
            self.db.last_truncated = False
        thread = threading.Thread(target=other_request)
        thread.start()
        thread.join()
        self.assertEqual(states, [False])
        self.assertTrue(self.db.last_truncated)

    def test_security_incident_distinguishes_same_name_signatures_by_sid(self):
        stamp = ips_web.now() - 10
        self.add(ts=stamp, sig='Shared name', sig_id=1001, flow_id=777)
        self.add(ts=stamp + .001, sig='Shared name', sig_id=1002, flow_id=777)
        total, incidents = self.db.security_incidents(stamp - 1, stamp + 1)
        self.assertEqual(total, 1)
        self.assertEqual(incidents[0]['signature_count'], 2)
        self.assertEqual(len(incidents[0]['signatures']), 2)

    def test_manual_rule_actions_and_quoted_parentheses(self):
        path = self.path / 'hunting.rules'
        with mock.patch.object(ips_web, 'HUNT_RULES', str(path)):
            for index, action in enumerate(('alert', 'block', 'drop', 'pass', 'reject', 'log')):
                rule = '%s tcp any any -> any any (msg:"%s"; content:"root(uid)"; sid:%d;)' % (
                    action, action, 9200100 + index)
                self.assertEqual(ips_web.hunt_rule_add(rule), (True, 'sid:%d' % (9200100 + index)))
            self.assertEqual(len(ips_web.hunt_rules_list()), 6)
            self.assertFalse(ips_web.hunt_rule_structure_valid('alert ip any any -> any any (msg:"bad";'))
            self.assertFalse(ips_web.hunt_rule_structure_valid('alert ip any any -> any any (msg:"bad);'))

    def test_drop_aggregates_use_the_exact_persisted_log_range(self):
        stamp = int(ips_web.now())
        times = [stamp - minutes * 60 for minutes in (40*1440,10*1440,2*1440,25*60,23*60,120,30,5)]
        for timestamp in times:
            self.add('drop', ts=timestamp, reason='rule', action='blocked')
        self.add('alert', ts=stamp-10)
        for start,end in [(stamp-minutes*60,stamp) for minutes in (15,60,360,1440,7*1440,30*1440)] + [(stamp-2*86400,stamp-86400)]:
            params = {'type':'drop','from':str(start),'to':str(end)}
            logs = self.app.events(params)
            summary = self.app.aggregate(params)
            expected = sum(start <= timestamp <= end for timestamp in times)
            self.assertEqual(summary['total'],expected)
            self.assertEqual(summary['total'],logs['total'])
            self.assertEqual(sum(row['count'] for row in summary['reasons']),expected)
        for params in ({'from':'nan'},{'to':'inf'},{'from':'-1'},{'from':'20','to':'10'}):
            with self.assertRaises(ValueError):
                self.app.aggregate(params)
        for i in range(70):
            self.db.security_summary(start=stamp-100-i,end=stamp)
        self.assertLessEqual(len(self.db.summary_cache),64)

    def test_persisted_series_matches_selected_window_without_memory(self):
        self.add(ts=ips_web.now() - 600)
        self.add('drop', ts=ips_web.now() - 20)
        self.add(ts=ips_web.now() - 7200)
        points = self.db.security_series(60, 2)
        self.assertEqual(sum(p['alerts'] for p in points), 2)
        self.assertEqual(sum(p['drops'] for p in points), 1)
        self.assertTrue(all(p['t'] % 120 == 0 for p in points))

    def test_hunt_non_sql_filter_has_required_fields(self):
        self.add(sig='Example MIXED alert')
        data = self.app.hunt({'q': 'sig:*mixed*', 'window': '60', 'icase': '1', 'source': 'db'})
        self.assertEqual(data['total'], 1)

    def test_hunt_paging_can_freeze_the_resolved_rolling_window(self):
        stamp = ips_web.now()
        self.add(ts=stamp-2, sig='Older record')
        self.add(ts=stamp-1, sig='First page record')
        query = {'window':'60','limit':'1','view':'list'}
        with mock.patch.object(ips_web, 'now', return_value=stamp):
            first = self.app.hunt(query)
        self.assertEqual(first['range'], [stamp-3600, stamp])
        self.add(ts=stamp+1, sig='New record after paging started')
        low, high = first['range']
        second = self.app.hunt({**query, 'from':str(low), 'to':str(high), 'offset':'1'})
        self.assertEqual(second['total'], first['total'])
        self.assertEqual(second['events'][0]['sig'], 'Older record')

    def test_sid_queries_do_not_get_lost_behind_protocol_scan_limits(self):
        stamp = ips_web.now()
        self.add(ts=stamp - 100, sig_id=2021076)
        for index in range(4):
            self.add('dns', ts=stamp - index, sig_id=None, sig='DNS ' + str(index))
        search = self.db.search_range
        def limited_search(*args, **kwargs):
            kwargs['max_scan'] = 2
            return search(*args, **kwargs)
        with mock.patch.object(self.db, 'search_range', side_effect=limited_search):
            for query in ('sid:*', 'sid: *', 'sid:2021076', 'sid: 2021076', 'sid: >=2021076'):
                with self.subTest(query=query):
                    data = self.app.hunt({'q': query, 'window': '60', 'source': 'db'})
                    self.assertEqual(data['total'], 1)
                    self.assertEqual(data['events'][0]['sig_id'], 2021076)
                    self.assertFalse(data['truncated'])

    def test_bad_ranges_do_not_crash_or_expand_queries(self):
        for params in ({'from': 'nan'}, {'from': 'inf'}, {'from': '20', 'to': '10'}, {'limit': 'bad'}):
            with self.assertRaises(ValueError):
                self.app.events(params)
        self.assertIn('error', self.app.hunt({'from': 'bad', 'q': 'src:192.0.2.1'}))
        self.assertIn('error', self.app.hunt({'from': 'nan'}))

    def test_replayed_context_is_deduplicated_and_microseconds_preserved(self):
        stamp = int(ips_web.now()) - 10
        rec = self.add('dns', ts=stamp + .0001, sig_id=None, sport=None)
        self.db.add(rec, json.dumps(rec))
        self.db.flush()
        self.add('dns', ts=stamp + .0002, sig_id=None, sport=None)
        self.assertEqual(self.db.stats()['rows'], 2)

    def test_flush_rolls_back_and_retries_after_database_error(self):
        real = self.db.conn
        self.db.add({'ts': ips_web.now(), 'type': 'dns'}, '{}')
        failing = mock.Mock(wraps=real)
        failing.executemany.side_effect = sqlite3.OperationalError('database is full')
        self.db.conn = failing
        self.db.flush()
        self.assertEqual(len(self.db.buf), 1)
        failing.rollback.assert_called_once()
        self.db.conn = real
        self.db.flush()
        self.assertEqual(self.db.stats()['rows'], 1)
        self.assertEqual(self.db.last_error, '')

    def test_dns_v3_and_vlan_array_are_persisted(self):
        raw = json.dumps({'timestamp': '2026-10-30T09:00:00+0800', 'event_type': 'dns',
                          'src_ip': '192.0.2.1', 'vlan': [12],
                          'dns': {'type': 'response', 'rrname': 'example.org', 'rrtype': 'A'}})
        rec, _ = self.store._parse(raw)
        self.assertEqual((rec['dns'], rec['rrtype'], rec['vlan']), ('example.org', 'A', 12))
        self.db.add(rec, raw)
        self.db.flush()
        self.assertEqual(self.db.stats()['rows'], 1)

    def test_rotation_starts_at_beginning_and_invalidates_old_offsets(self):
        def event(name):
            return json.dumps({'timestamp': ips_web.iso(ips_web.now()), 'event_type': 'dns',
                               'dns': {'rrname': name}, 'src_ip': '192.0.2.1'}) + '\n'
        path = self.path / 'eve.json'
        self.store.initial_tail = 10000
        path.write_text(event('first.test'))
        self.store.ingest()
        old_id = self.store.events[-1]['id']
        path.rename(self.path / 'eve.json.1')
        path.write_text(event('second.test') + event('third.test'))
        self.store.initial_tail = 16
        self.store.last_ingest = 0
        self.store.ingest()
        self.assertIsNone(self.store.detail(old_id))
        self.assertIn('third.test', self.store.detail(self.store.events[-1]['id']))
        self.assertEqual(self.store.events[-2]['dns'], 'second.test')


class SourceCatalogCase(unittest.TestCase):
    """规则源目录解析（snort-update CLI 输出，带 ANSI 码）。"""

    SAMPLE = (
        "\x1b[1;36mName\x1b[0m: \x1b[1;35met/open\x1b[0m\n"
        "  Vendor: Proofpoint\n"
        "  Summary: Emerging Threats Open Ruleset\n"
        "  License: MIT\n"
        "Name: et/pro\n"
        "  Vendor: Proofpoint\n"
        "  Summary: ET Pro Ruleset\n"
        "  Parameters: secret-code\n"
    )

    def test_parse_source_catalog(self):
        catalog = ips_web.parse_source_catalog(self.SAMPLE)
        self.assertEqual(len(catalog), 2)
        self.assertEqual(catalog[0]["name"], "et/open")
        self.assertEqual(catalog[0]["vendor"], "Proofpoint")
        self.assertEqual(catalog[0]["summary"], "Emerging Threats Open Ruleset")
        self.assertFalse(catalog[0]["subscribed"])
        self.assertTrue(catalog[1]["subscribed"])

    def test_parse_enabled_sources(self):
        enabled = ips_web.parse_enabled_sources("Enabled sources:\n  - et/open\n  - tgreen/hunting\n")
        self.assertEqual(enabled, {"et/open", "tgreen/hunting"})

    def test_source_name_validation(self):
        self.assertTrue(ips_web.SOURCE_NAME_RE.match("et/open"))
        self.assertTrue(ips_web.SOURCE_NAME_RE.match("abuse.ch/sslbl-ja3"))
        self.assertFalse(ips_web.SOURCE_NAME_RE.match("../x"))
        self.assertFalse(ips_web.SOURCE_NAME_RE.match("et/open;id"))

    def test_batch_values_normalizes_input(self):
        body = {"values": ["sid:1", " sid:1 ", "", "sid:2", None, "sid:2"]}
        self.assertEqual(ips_web._batch_values(body, "values", "value"), ["sid:1", "sid:2"])
        self.assertEqual(ips_web._batch_values({"value": "sid:9"}, "values", "value"), ["sid:9"])
        self.assertEqual(ips_web._batch_values({}, "values", "value"), [])
        many = {"values": ["s%d" % i for i in range(500)]}
        self.assertEqual(ips_web._batch_values(many, "values", "value"), many["values"])

    def test_batch_result_message(self):
        ok = ips_web._batch_result(3, [], "成功 3 条")
        self.assertEqual(ok, {"ok": True, "message": "成功 3 条", "added": 3, "errors": []})
        mixed = ips_web._batch_result(2, ["sid:1（已存在）"], "成功")
        self.assertTrue(mixed["ok"])
        self.assertIn("成功 2 条", mixed["message"])
        self.assertIn("跳过/失败 1 条", mixed["message"])


class RejectToggleCase(unittest.TestCase):
    """reject 改写：drop.conf + modify.conf 配套两行的增删切换。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.drop = self.tmp / "drop.conf"
        self.modify = self.tmp / "modify.conf"
        self.drop.write_text("group:a*\ngroup:b*\n", encoding="utf-8")
        patchers = [
            mock.patch.object(ips_web, "DROP_CONF", str(self.drop)),
            mock.patch.object(ips_web, "MODIFY_CONF", str(self.modify)),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_reject_toggle_pairing(self):
        ok, _ = ips_web.reject_add("group:a*")
        self.assertTrue(ok)
        # drop.conf 不动，modify.conf 加配套行
        self.assertIn("group:a*", self.drop.read_text(encoding="utf-8"))
        self.assertIn("metadata-add 'group:a*' ipsweb.reject true", self.modify.read_text(encoding="utf-8"))
        self.assertIn("'group:a*' ^drop reject", self.modify.read_text(encoding="utf-8"))
        # 治理状态：drop 条目带 reject 标记
        gov = ips_web.governance_state()
        flags = {d["value"]: d["reject"] for d in gov["drop"]}
        self.assertEqual(flags, {"group:a*": True, "group:b*": False})
        self.assertEqual(gov["reject"], ["group:a*"])
        # 切回 drop
        ok, _ = ips_web.reject_remove("group:a*")
        self.assertTrue(ok)
        self.assertNotIn("group:a*", self.modify.read_text(encoding="utf-8"))
        self.assertIn("group:a*", self.drop.read_text(encoding="utf-8"))
        # reject_add 会自动补 drop.conf 行
        ok, _ = ips_web.reject_add("group:new*")
        self.assertTrue(ok)
        self.assertIn("group:new*", self.drop.read_text(encoding="utf-8"))
        self.assertIn("metadata-add 'group:new*' ipsweb.reject true", self.modify.read_text(encoding="utf-8"))
        self.assertIn("'group:new*' ^drop reject", self.modify.read_text(encoding="utf-8"))

    def test_drop_remove_purges_reject_line(self):
        ips_web.reject_add("group:b*")
        ok, _ = ips_web.drop_remove("group:b*")
        self.assertTrue(ok)
        self.assertNotIn("group:b*", self.modify.read_text(encoding="utf-8"))
        self.assertNotIn("group:b*", self.drop.read_text(encoding="utf-8"))

    def test_sid_selector_uses_snort_update_numeric_filter(self):
        self.assertEqual(ips_web._selector_filter("sid:2100498"), "2100498")
        ok, _ = ips_web.reject_add("sid:2100498")
        self.assertTrue(ok)
        drop_line = [line for line in self.drop.read_text(encoding="utf-8").splitlines()
                     if "2100498" in line][0]
        metadata_line = [line for line in self.modify.read_text(encoding="utf-8").splitlines()
                         if "2100498" in line and "metadata-add" in line][0]
        modify_line = [line for line in self.modify.read_text(encoding="utf-8").splitlines()
                       if "2100498" in line and "^drop reject" in line][0]
        self.assertTrue(drop_line.startswith("2100498 # ips-web-selector-b64="))
        self.assertTrue(metadata_line.startswith("metadata-add 2100498 ipsweb.reject true #"))
        self.assertTrue(modify_line.startswith("2100498 ^drop reject # ips-web-selector-b64="))
        self.assertEqual(ips_web._selector_from_line(drop_line), "sid:2100498")
        gov = ips_web.governance_state()
        self.assertEqual(gov["drop"][-1], {"value": "sid:2100498", "reject": True})
        self.assertEqual(gov["reject"], ["sid:2100498"])

    def test_msg_selector_is_translated_to_rule_regex_filter(self):
        self.assertEqual(ips_web._selector_filter("msg:ET TOR"), 're:msg:"ET\\ TOR')
        self.assertEqual(ips_web._selector_filter("msg:ET MALWARE*"), 're:msg:"ET\\ MALWARE.*')
        ok, _ = ips_web.reject_add("msg:ET MALWARE*")
        self.assertTrue(ok)
        self.assertIn('re:msg:"ET', self.drop.read_text(encoding="utf-8"))
        self.assertIn(' ^drop reject', self.modify.read_text(encoding="utf-8"))
        self.assertIn('ipsweb.reject true', self.modify.read_text(encoding="utf-8"))
        gov = ips_web.governance_state()
        self.assertEqual(gov["drop"][-1], {"value": "msg:ET MALWARE*", "reject": True})

    def test_normalize_migrates_legacy_sid_lines(self):
        self.drop.write_text("sid:2100498\n", encoding="utf-8")
        self.modify.write_text("sid:2100498 ^drop reject\n", encoding="utf-8")
        ips_web.normalize_selector_conf(str(self.drop))
        ips_web.normalize_selector_conf(str(self.modify), modify=True)
        self.assertIn("2100498 # ips-web-selector-b64=", self.drop.read_text(encoding="utf-8"))
        self.assertNotIn("\nsid:2100498\n", self.drop.read_text(encoding="utf-8"))
        self.assertIn("metadata-add 2100498 ipsweb.reject true", self.modify.read_text(encoding="utf-8"))
        self.assertIn("2100498 ^drop reject # ips-web-selector-b64=",
                      self.modify.read_text(encoding="utf-8"))
        gov = ips_web.governance_state()
        self.assertEqual(gov["drop"], [{"value": "sid:2100498", "reject": True}])

    def test_normalize_adds_missing_metadata_marker(self):
        line = "'group:a*' ^drop reject" + ips_web._selector_marker("group:a*")
        self.modify.write_text(line + "\n", encoding="utf-8")
        ips_web.normalize_selector_conf(str(self.modify), modify=True)
        self.assertIn("metadata-add 'group:a*' ipsweb.reject true", self.modify.read_text(encoding="utf-8"))
        self.assertIn("'group:a*' ^drop reject", self.modify.read_text(encoding="utf-8"))
        gov = ips_web.governance_state()
        self.assertEqual(gov["drop"], [
            {"value": "group:a*", "reject": True},
            {"value": "group:b*", "reject": False},
        ])

    def test_normalize_repairs_reversed_metadata_and_is_idempotent(self):
        marker = ips_web._selector_marker('group:feodotracker*')
        self.modify.write_text(
            '# Preserve comment\ngroup:feodotracker* metadata-add ipsweb.reject true' + marker +
            '\ngroup:feodotracker* ^drop reject' + marker +
            '\nmetadata-add 1001 vendor value\n', encoding='utf-8')
        ips_web.normalize_selector_conf(str(self.modify), modify=True)
        fixed = self.modify.read_text(encoding='utf-8')
        self.assertIn("metadata-add 'group:feodotracker*' ipsweb.reject true", fixed)
        self.assertNotIn('group:feodotracker* metadata-add', fixed)
        self.assertEqual(fixed.count('ipsweb.reject true'), 1)
        self.assertIn('# Preserve comment\n', fixed)
        self.assertIn('metadata-add 1001 vendor value\n', fixed)
        ips_web.normalize_selector_conf(str(self.modify), modify=True)
        self.assertEqual(self.modify.read_text(encoding='utf-8'), fixed)

    def test_modify_matchers_roundtrip_spaces_quotes_and_backslashes(self):
        for selector in ('group:a*', 'sid:2100498', 'msg:ET MALWARE*',
                         "msg:User's agent*", r're:ET\s+MALWARE'):
            with self.subTest(selector=selector):
                match = ips_web._selector_filter(selector)
                meta = ips_web._selector_metadata_line(selector).rsplit(' #', 1)[0]
                modify = ips_web._selector_config_line(selector, True).rsplit(' #', 1)[0]
                self.assertEqual(shlex.split(meta), ['metadata-add', match, 'ipsweb.reject', 'true'])
                self.assertEqual(shlex.split(modify), [match, '^drop', 'reject'])



class RuleGroupCase(unittest.TestCase):
    def test_cached_and_online_jobs_share_validation_actions_and_reload(self):
        sysinfo = ips_web.SysInfo()
        def immediate_thread(*, target, daemon):
            thread = mock.Mock(); thread.start.side_effect = target; return thread
        with mock.patch.object(ips_web.threading,'Thread',side_effect=immediate_thread), \
             mock.patch.object(ips_web.subprocess,'run',return_value=mock.Mock(stdout='updated\n',returncode=0)) as run, \
             mock.patch.object(ips_web,'prepare_thresholds') as prepare, \
             mock.patch.object(sysinfo.engine,'call',return_value={'ruleset-reload-rules':True}) as reload:
            for offline in (True,False):
                run.reset_mock();prepare.reset_mock();reload.reset_mock()
                self.assertTrue(sysinfo.update_rules(offline=offline)['ok'])
                first=run.call_args_list[0].args[0]
                self.assertEqual('--offline' in first,offline)
                self.assertEqual(first[0],'/usr/local/bin/ips-snort-rules')
                self.assertIn('-T',run.call_args_list[1].args[0])
                prepare.assert_called_once()
                reload.assert_called_once_with(['ruleset-reload-rules'],timeout=300)
                self.assertEqual(sysinfo.update_status()['rc'],0)

    def test_group_inventory_reads_all_archives_and_distinguishes_stopped_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cache = root / 'cache'; cache.mkdir(); dist = root / 'dist'; dist.mkdir()
            rules = root / 'snort.rules'
            line = lambda sid, extra='': 'alert tcp any any -> any any (msg:"Fixture"; sid:%d; %srev:1;)\n' % (sid, extra)
            rules.write_text(line(1).replace('alert ', 'reject ', 1) + line(2, 'noalert; ') + line(3) + line(4))
            with tarfile.open(cache / 'aaa-ptopen.rules.tar.gz', 'w:gz') as archive:
                raw = (line(1) + line(2, 'noalert; ')).encode()
                member = tarfile.TarInfo('rules/ptopen-malware.rules'); member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
            (cache / 'bbb-snort.rules').write_text(line(3))
            (cache / 'ccc-stopped.rules').write_text(line(4))
            (cache / 'old-unknown.rules').write_text(line(1))
            (dist / 'stream-events.rules').write_text(line(5).replace('; sid:5;', '; \\\n sid:5;'))
            patches = {'UPDATE_CACHE_DIR': str(cache), 'DIST_RULES_DIR': str(dist), 'SOURCES_DIR': str(root / 'sources'),
                       'RULES_FILE': str(rules), '_GROUP_CACHE': {'key': None, 'rows': []}}
            with mock.patch.multiple(ips_web, **patches), mock.patch.object(ips_web, '_source_cache_metadata',
                    return_value={'aaa': ('ptrules/open', True), 'bbb': ('echap/stalkerware', True), 'ccc': ('old/feed', False)}):
                groups = {r['name']: r for r in ips_web.rule_group_catalog()}
                self.assertEqual((groups['ptopen-malware']['total'], groups['ptopen-malware']['compiled'], groups['ptopen-malware']['blockable']), (2, 2, 1))
                self.assertEqual(groups['snort']['source'], 'echap/stalkerware')
                self.assertEqual(groups['stopped']['compiled'], 1)
                self.assertEqual(groups['stopped']['blockable'], 0)
                self.assertIn('stream-events', ips_web.rule_groups())
                self.assertEqual(groups['stream-events']['total'], 1)
                self.assertNotIn('stopped', ips_web.rule_groups())
                app = ips_web.App.__new__(ips_web.App)
                self.assertEqual(app.rules_search('1')['rules'][0]['action'], 'reject')
                self.assertEqual(app.rules_search('1')['rules'][0]['origins'], [{'group':'ptopen-malware','source':'ptrules/open'}])
                members = ips_web.rule_group_detail('ptopen-malware','ptrules/open',limit=1)
                self.assertEqual(members['total'],2)
                self.assertEqual(members['rules'][0]['action'],'reject')
                self.assertTrue(members['rules'][0]['enabled'])
                self.assertEqual(ips_web.rule_group_detail('ptopen-malware','ptrules/open',offset=1)['rules'][0]['sid'],2)
                self.assertEqual(ips_web.rule_group_detail('stream-events','Snort')['rules'][0]['action'],'')
                self.assertFalse(ips_web.rule_group_detail('stream-events','Snort')['rules'][0]['enabled'])
                self.assertEqual(ips_web.rule_group_detail('stream-events','Snort',query='5')['total'],1)
                self.assertEqual(ips_web.rule_group_detail('stream-events','wrong')['total'],0)
                self.assertEqual(ips_web.rule_group_detail('../../etc/passwd')['total'],0)
                self.assertEqual(sum(r['drop'] for r in ips_web.RuleBook().categories()), 1)
                disabled = root / 'disabled.conf'; disabled.write_text('sid:5\n')
                with mock.patch.object(ips_web, 'DISABLE_CONF', str(disabled)):
                    self.assertEqual(ips_web.governance_state(details=True)['disable'][0]['name'], 'Fixture')

    def test_ban_ipv6_alternate_spelling_is_a_duplicate(self):
        with mock.patch.object(ips_web.RuleBook, '_load_bans', return_value=[{'type':'ip','value':'2001:0db8:0:0:0:0:0:1'}]), \
             mock.patch.object(ips_web.RuleBook, '_save_bans') as save:
            self.assertFalse(ips_web.RuleBook.ban('2001:db8::1')[0])
            save.assert_not_called()

    def test_picker_exclusion_is_scoped_normalized_and_paginated_before_count(self):
        rules = [{'sid':sid,'msg':'Fixture %d' % sid,'msg_lower':'fixture %d' % sid,'action':'alert'} for sid in range(1,8)]
        app = ips_web.App.__new__(ips_web.App)
        app._rules_index_cache = (1, {'rules':rules,'by_sid':{r['sid']:r for r in rules}})
        with tempfile.TemporaryDirectory() as directory:
            paths = {key: str(Path(directory) / key) for key in
                     ('DROP_CONF','MODIFY_CONF','ACTION_CONF','DISABLE_CONF','THRESHOLD_CONF','SUPPRESS_LUA')}
            for path in paths.values(): Path(path).write_text('')
            Path(paths['DISABLE_CONF']).write_text('1\ngroup:emerging-*\n')
            Path(paths['ACTION_CONF']).write_text('reject sid:0002\n')
            Path(paths['THRESHOLD_CONF']).write_text('suppress gen_id 1, sig_id 3\n')
            with mock.patch.multiple(ips_web, **paths), mock.patch.object(app, 'rules_index', return_value=app._rules_index_cache[1]), \
                 mock.patch.object(ips_web, 'rule_groups', return_value=['emerging-scan','other']), \
                 mock.patch.object(ips_web, 'rules_with_origins', side_effect=lambda rows:rows):
                page = app.rules_search('', browse=True, limit=2, offset=4, exclude='disable')
                self.assertEqual(page['total'], 6)
                self.assertEqual([r['sid'] for r in page['rules']], [3,2])
                self.assertEqual(page['groups'], ['other'])
                self.assertEqual(app.rules_search('2', exclude='action')['total'], 0)
                self.assertEqual(app.rules_search('2', exclude='action', include='sid:0002')['total'], 1)
                self.assertEqual(app.rules_search('2', exclude='suppress')['total'], 1)
                self.assertTrue(ips_web.suppress_add(33)[0])
                self.assertFalse(ips_web.suppress_add(3)[0])
                self.assertFalse(ips_web.disable_add('group:emerging-scan.rules')[0])

    def test_disable_sid_is_translated_and_roundtrips_without_comment_leaks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'disable.conf'; path.write_text('')
            with mock.patch.object(ips_web, 'DISABLE_CONF', str(path)):
                self.assertTrue(ips_web.disable_add('sid:1234')[0])
                self.assertTrue(path.read_text().startswith('1234 # ips-web-selector-b64='))
                self.assertFalse(ips_web.disable_add('sid:1234')[0])
                self.assertIn({'value': 'sid:1234'}, ips_web.governance_state()['disable'])
                self.assertTrue(ips_web.disable_remove('sid:1234')[0])
                self.assertEqual(path.read_text(), '')




class SuppressionActivationCase(unittest.TestCase):
    def test_inactive_sids_are_retained_and_reactivated_without_unknown_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); config=root/'threshold.config'; rules=root/'snort.rules'
            rules.write_text('alert tcp any any -> any any (msg:"one"; sid:11; rev:1;)\nalert tcp any any -> any any (msg:"two"; gid:2; sid:12; rev:1;)\n')
            original='# preserve\nsuppress gen_id 1, sig_id 11\nsuppress gen_id 2, sig_id 12, track by_src, ip 192.0.2.1\nsuppress gen_id 1, sig_id 13\nsuppress gen_id 0, sig_id 0, track by_src, ip 192.0.2.0/24\n'
            config.write_text(original)
            with mock.patch.multiple(ips_web,THRESHOLD_CONF=str(config),SUPPRESS_LUA=str(root/'suppress.lua'),RULES_FILE=str(rules),SNORT_CONF=str(root/'missing.yaml'),
                    LOCAL_RULES=str(root/'none'),BAN_RULES=str(root/'none'),HUNT_RULES=str(root/'none')):
                result=ips_web.prepare_thresholds()
                self.assertEqual((result['active'],result['pending']),(3,1))
                self.assertNotIn('\nsuppress gen_id 1, sig_id 13\n',config.read_text())
                logical=''.join(ips_web.suppression_line(line)+'\n' for line in config.read_text().splitlines())
                self.assertEqual(logical,original)
                self.assertFalse(ips_web.prepare_thresholds()['changed'])
                rows=ips_web.governance_state()['suppress']
                self.assertTrue(next(row for row in rows if row['sid']==13)['pending'])
                self.assertFalse(ips_web.suppress_add(13)[0])
                rules.write_text(rules.read_text()+'alert tcp any any -> any any (msg:"three"; sid:13; rev:1;)\n')
                self.assertEqual(ips_web.prepare_thresholds()['pending'],0)
                self.assertIn('\nsuppress gen_id 1, sig_id 13\n',config.read_text())
                self.assertTrue(ips_web.suppress_add(99)[0])
                self.assertTrue(next(row for row in ips_web.governance_state()['suppress'] if row['sid']==99)['pending'])
                self.assertTrue(ips_web.suppress_remove(99)[0])
                self.assertNotIn(99,[row['sid'] for row in ips_web.governance_state()['suppress']])
                self.assertIn('track by_src, ip 192.0.2.1',config.read_text())

    def test_threshold_migration_failure_keeps_original_and_empty_inventory_preserves_it(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'threshold.config'; target.write_text('suppress gen_id 1, sig_id 123\n')
            with mock.patch.object(ips_web,'THRESHOLD_CONF',str(target)),mock.patch.object(ips_web,'SUPPRESS_LUA',str(Path(directory)/'suppress.lua')),mock.patch.object(ips_web,'active_rule_ids',return_value=set()):
                with mock.patch.object(ips_web.os,'replace',side_effect=OSError('fixture failure')):
                    with self.assertRaises(OSError): ips_web.prepare_thresholds()
                self.assertEqual(target.read_text(),'suppress gen_id 1, sig_id 123\n')
                self.assertFalse(Path(str(target)+'.ips-web-tmp').exists())
            with mock.patch.object(ips_web,'THRESHOLD_CONF',str(target)),mock.patch.object(ips_web,'SUPPRESS_LUA',str(Path(directory)/'suppress.lua')),mock.patch.object(ips_web,'active_rule_ids',return_value=None):
                self.assertFalse(ips_web.prepare_thresholds()['changed'])






class RuleSearchCase(unittest.TestCase):
    def test_catalog_paginates_without_losing_total(self):
        rules = [{"sid": 1000 + i, "msg": "Test %d" % i, "msg_lower": "test %d" % i,
                  "action": "alert"} for i in range(125)]
        app = object.__new__(ips_web.App)
        app._rules_index_cache = (1, {"rules": rules, "by_sid": {r['sid']: r for r in rules}})
        with mock.patch.object(app, 'rules_index', return_value=app._rules_index_cache[1]):
            first = app.rules_search('Test', limit=50)
            second = app.rules_search('Test', limit=50, offset=50)
            last = app.rules_search('Test', limit=50, offset=100)
            self.assertEqual((first['total'], second['total'], last['total']), (125, 125, 125))
            self.assertEqual((len(first['rules']), len(second['rules']), len(last['rules'])), (50, 50, 25))
            self.assertFalse({r['sid'] for r in first['rules']} & {r['sid'] for r in second['rules']})
            self.assertEqual(app.rules_search('', browse=True)['total'], 125)
            self.assertEqual(app.rules_search('')['total'], 20)

    def test_action_change_upserts_selector_and_preserves_other_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'actions.conf'
            path.write_text('# Keep this comment\ndrop sid:1001\nreject msg:ET SCAN*\n')
            with mock.patch.object(ips_web, 'ACTION_CONF', str(path)):
                self.assertTrue(ips_web.action_add('reject', 'sid:1001')[0])
                self.assertTrue(ips_web.action_add('reject', 'sid:1001')[0])
                lines = path.read_text().splitlines()
                self.assertEqual(lines.count('reject sid:1001'), 1)
                self.assertNotIn('drop sid:1001', lines)
                self.assertIn('reject msg:ET SCAN*', lines)
                self.assertIn('# Keep this comment', lines)
                self.assertFalse(ips_web.action_add('drop', 'sid:1001\nreject sid:2')[0])

    def test_partial_batch_result_identifies_failed_entries(self):
        result = ips_web._batch_result(1, ['sid:1002'], 'saved')
        self.assertTrue(result['ok'])
        self.assertEqual(result['added'], 1)
        self.assertEqual(result['errors'], ['sid:1002'])

    def test_rule_line_regex(self):
        line = ('drop dns $HOME_NET any -> any any (msg:"PTS X (a[.]com)"; '
                'content:"a.com"; classtype:trojan-activity; sid:3330001; rev:1;)')
        match = ips_web._RULE_LINE.match(line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "drop")
        self.assertEqual(match.group(2), "PTS X (a[.]com)")
        self.assertEqual(match.group(3), "3330001")
        self.assertEqual(ips_web._RULE_CLASS.search(line).group(1), "trojan-activity")
        # 被注释掉的规则不参与搜索
        self.assertIsNone(ips_web._RULE_LINE.match('# alert ip any any -> any any (msg:"X"; sid:1;)'))
        spaced = 'reject http any any -> any any (flow: established; msg: "PT \\"quoted\\" action"; sid: 1234; rev:1;)'
        match = ips_web._RULE_LINE.match(spaced)
        self.assertIsNotNone(match)
        self.assertEqual((match.group(1), match.group(3)), ('reject', '1234'))

    def test_rules_search_all_parameters_and_origins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snort.rules'
            path.write_text('alert tcp $HOME_NET any -> 198.51.100.9 8443 (msg:"Example"; flow:to_server; content:"needle"; metadata:deployment Perimeter; classtype:trojan-activity; sid:101; rev:7;)\n'
                            'reject udp any any -> any 53 (msg:"Other"; sid:102; rev:1;)\n'
                            '# alert tcp any any -> any any (msg:"Disabled"; sid:103;)\n')
            app = ips_web.App.__new__(ips_web.App)
            catalog = [{'name':'sample-group', 'label':'Readable Label', 'source':'vendor/feed', 'source_enabled':True}]
            origins = {101:[{'group':'sample-group', 'source':'vendor/feed'}],
                       102:[{'group':'sample-group', 'source':'vendor/feed'}]}
            with mock.patch.object(ips_web, 'RULES_FILE', str(path)), \
                 mock.patch.object(ips_web, 'rule_group_catalog', return_value=catalog), \
                 mock.patch.dict(ips_web._GROUP_CACHE, rows=catalog, origins=origins):
                for query in ('TCP', '$HOME_NET', '198.51.100.9', '8443', 'flow:to_server',
                              'needle', 'deployment Perimeter', 'trojan-activity', 'rev:7', 'sid:101'):
                    with self.subTest(query=query):
                        result = app.rules_search(query)
                        self.assertEqual([r['sid'] for r in result['rules']], [101])
                        self.assertNotIn('search_text', result['rules'][0])
                self.assertEqual(app.rules_search('reject')['rules'][0]['sid'], 102)
                for query in ('SAMPLE-GROUP', 'readable label', 'VENDOR/FEED'):
                    page = app.rules_search(query, limit=1, offset=1)
                    self.assertEqual(page['total'], 2)
                    self.assertEqual(page['rules'][0]['sid'], 102)
                self.assertEqual(app.rules_search('Disabled')['total'], 0)
                self.assertEqual(app.rules_search('sid:10')['total'], 0)
                self.assertEqual(app.rules_search('10')['total'], 2)
                with mock.patch.object(ips_web, 'configured_selectors', return_value={'sid:101'}):
                    self.assertEqual(app.rules_search('vendor/feed', exclude='disable')['total'], 1)
                groups = app.rules_search('', browse=True)
                self.assertIn('vendor/feed', groups['group_search']['sample-group'])

    def test_rules_search_by_sid_and_msg(self):
        rule_a = {"sid": 2100498, "msg": "ET MALWARE Fake", "action": "drop",
                  "classtype": "trojan-activity", "msg_lower": "et malware fake"}
        rule_b = {"sid": 3000000, "msg": "SNORT TRAFFIC-ID: netflix", "action": "alert",
                  "classtype": "", "msg_lower": "snort traffic-id: netflix"}
        app = object.__new__(ips_web.App)
        app._rules_index_cache = (1, {"rules": [rule_a, rule_b],
                                      "by_sid": {2100498: rule_a, 3000000: rule_b}})
        from unittest import mock
        with mock.patch.object(app, 'rules_index', return_value=app._rules_index_cache[1]):
            by_sid = app.rules_search("2100498")
            self.assertEqual(by_sid["total"], 1)
            self.assertEqual(by_sid["rules"][0]["msg"], "ET MALWARE Fake")
            by_msg = app.rules_search("NETFLIX")
            self.assertEqual([r["sid"] for r in by_msg["rules"]], [3000000])
            prefixed = app.rules_search("sid:3000000")
            self.assertEqual(prefixed["total"], 1)
            empty = app.rules_search("")
            self.assertEqual([r["sid"] for r in empty["rules"]], [3000000, 2100498])
            self.assertEqual(empty["total"], 2)


class RuleScheduleCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / 'schedule.json')
        self.sys = mock.Mock()
        self.sys.update_status.return_value = {'state': 'idle'}
        self.sys.update_rules.return_value = {'ok': True}
        self.schedule = ips_web.RuleUpdateSchedule(self.sys, self.path)
        self.setting = dict(enabled=True, frequency='daily', time='04:00', weekday=0)

    def due(self):
        self.schedule.configure(self.setting)
        self.schedule.data['next_run'] = ips_web.now() - 1
        self.schedule._save()

    def test_disabled_by_default_and_settings_survive_restart(self):
        self.schedule.tick()
        self.sys.update_rules.assert_not_called()
        self.assertFalse(Path(self.path).exists())
        self.schedule.configure(self.setting)
        restored = ips_web.RuleUpdateSchedule(self.sys, self.path)
        self.assertTrue(restored.status()['enabled'])
        self.assertGreater(restored.status()['next_run'], ips_web.now())
        restored.configure(dict(self.setting, enabled=False))
        restored.tick()
        self.sys.update_rules.assert_not_called()
        self.assertFalse(ips_web.RuleUpdateSchedule(self.sys, self.path).status()['enabled'])

    def test_daily_weekly_local_time_boundaries(self):
        dt = ips_web.datetime(2026, 10, 31, 4, 0)
        daily = ips_web.datetime.fromtimestamp(self.schedule.next_time(self.setting, dt.timestamp()))
        self.assertEqual(daily, ips_web.datetime(2026, 11, 1, 4, 0))
        weekly = dict(self.setting, frequency='weekly', weekday=0)
        target = ips_web.datetime.fromtimestamp(self.schedule.next_time(weekly, dt.timestamp()))
        self.assertEqual(target, ips_web.datetime(2026, 11, 2, 4, 0))
        self.assertEqual(self.schedule.next_time(weekly, target.timestamp()),
                         (target + ips_web.timedelta(days=7)).timestamp())

    def test_overdue_is_run_once_and_result_is_persisted(self):
        self.due()
        self.schedule.tick()
        self.sys.update_rules.assert_called_once()
        self.assertEqual(self.sys.update_rules.call_args.kwargs['trigger'], 'scheduled')
        self.schedule.tick()
        restarted = ips_web.RuleUpdateSchedule(self.sys, self.path)
        restarted.tick()
        self.sys.update_rules.assert_called_once()
        self.assertEqual(restarted.status()['last_run']['state'], 'interrupted')
        callback = self.sys.update_rules.call_args.kwargs['on_complete']
        callback(dict(state='done', started=123, finished=456, rc=1, lines=['download failed']))
        result = ips_web.RuleUpdateSchedule(self.sys, self.path).status()['last_run']
        self.assertEqual(result['rc'], 1)
        self.assertEqual(result['lines'], ['download failed'])

    def test_busy_and_manual_start_race_remain_pending(self):
        self.due()
        due = self.schedule.data['next_run']
        self.sys.update_status.return_value = {'state': 'running'}
        self.schedule.tick()
        self.sys.update_rules.assert_not_called()
        self.assertEqual(self.schedule.data['next_run'], due)
        self.sys.update_status.return_value = {'state': 'done'}
        self.sys.update_rules.return_value = {'ok': False, 'error': 'already running'}
        self.schedule.tick()
        self.assertEqual(self.schedule.data['next_run'], due)
        self.sys.update_rules.return_value = {'ok': True}
        self.schedule.tick()
        self.assertGreater(self.schedule.data['next_run'], ips_web.now())

    def test_bad_input_and_write_failure_do_not_change_settings(self):
        for change in ({'enabled': 'false'}, {'time': '24:00'}, {'time': '4:00'},
                       {'frequency': 'hourly'}, {'weekday': 7}, {'weekday': True}):
            with self.assertRaises(ValueError):
                self.schedule.configure(dict(self.setting, **change))
        with mock.patch.object(self.schedule, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.schedule.configure(self.setting)
        self.assertFalse(self.schedule.status()['enabled'])
        self.due()
        with mock.patch.object(self.schedule, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.schedule.tick()
        self.sys.update_rules.assert_not_called()

    def test_corrupt_file_fails_closed(self):
        for text in ('{', '[]', '{"enabled":true}'):
            Path(self.path).write_text(text)
            restored = ips_web.RuleUpdateSchedule(self.sys, self.path)
            self.assertFalse(restored.status()['enabled'])
            self.assertTrue(restored.status()['error'])

    def test_scheduled_worker_uses_online_pipeline_and_records_success(self):
        self.schedule.sys = ips_web.SysInfo()
        self.due()
        def immediate_thread(*,target,daemon):
            thread=mock.Mock();thread.start.side_effect=target;return thread
        with mock.patch.object(ips_web.threading,'Thread',side_effect=immediate_thread), \
             mock.patch.object(ips_web.subprocess,'run',return_value=mock.Mock(stdout='updated\n',returncode=0)) as run, \
             mock.patch.object(ips_web,'prepare_thresholds'), \
             mock.patch.object(self.schedule.sys.engine,'call',return_value={'ruleset-reload-rules':True}):
            self.schedule.tick()
        self.assertNotIn('--offline',run.call_args_list[0].args[0])
        restored=ips_web.RuleUpdateSchedule(self.sys,self.path)
        self.assertEqual(restored.status()['last_run']['rc'],0)
        self.assertEqual(restored.status()['last_run']['lines'],['updated'])


class DatabaseCapacityCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = str(Path(self.directory.name) / 'events.db')
        self.db = ips_web.EventDB(self.path)

    def tearDown(self):
        self.db.conn.close()
        self.directory.cleanup()

    def test_capacity_persists_without_deleting_events(self):
        self.db.add({'ts': ips_web.now(), 'type': 'alert'}, '{}')
        self.db.flush()
        stats = self.db.configure_capacity(512)
        self.assertEqual(stats['cap'], 512 << 20)
        self.assertEqual(stats['rows'], 1)
        restored = ips_web.EventDB(self.path)
        try:
            self.assertEqual(restored.cap, 512 << 20)
            self.assertEqual(restored.stats()['rows'], 1)
        finally:
            restored.conn.close()

    def test_invalid_values_never_change_capacity(self):
        original = self.db.cap
        for value in (None, True, False, '512', 64.5, 63, 1048577, -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.db.configure_capacity(value)
            self.assertEqual(self.db.cap, original)
        self.assertFalse(Path(self.path + '.settings.json').exists())

    def test_write_failure_keeps_live_limit(self):
        with mock.patch.object(ips_web, 'atomic_text', side_effect=OSError('read only')):
            with self.assertRaises(OSError):
                self.db.configure_capacity(512)
        self.assertEqual(self.db.cap, self.db.CAP_BYTES)

    def test_corrupt_settings_keep_default(self):
        Path(self.path + '.settings.json').write_text('{invalid')
        restored = ips_web.EventDB(self.path)
        try:
            self.assertEqual(restored.cap, self.db.CAP_BYTES)
            self.assertIn('容量设置失败', restored.last_error)
        finally:
            restored.conn.close()


if __name__ == "__main__":
    unittest.main()
