"""Nonblocking overview snapshots, read-only isolation and bounded worker lifecycle."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('snapshot_backend', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
backend = importlib.util.module_from_spec(spec)
loader.exec_module(backend)


class NetworkSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = backend.EventDB(str(Path(self.temp.name) / 'events.db'))
        self.tick = 100.0
        self.cache = backend.NetworkSnapshots(self.db, clock=lambda: self.tick)
        self.cache.QUERY_GAP_SECONDS = 0
        self.stamp = backend.now() - 100

    def tearDown(self):
        self.cache.close()
        self.assertTrue(self.cache.thread is None or not self.cache.thread.is_alive())
        self.db.conn.close()
        self.temp.cleanup()

    def add(self, stamp=None):
        event = dict(timestamp=backend.iso(self.stamp if stamp is None else stamp),
                     event_type='flow', src_ip='192.0.2.1', dest_ip='198.51.100.1',
                     proto='TCP', app_proto='tls', flow_id=123,
                     flow=dict(bytes_toserver=100, bytes_toclient=200,
                               pkts_toserver=1, pkts_toclient=2))
        self.db.add(*backend.EventStore._parse(json.dumps(event)))
        self.db.flush()

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.01)
        self.fail('Background snapshot did not reach the expected state')

    def get(self, start=None, end=None, rolling='rolling'):
        high = backend.now() if end is None else end
        low = high - 86400 if start is None else start
        return self.cache.get(low, high, rolling)

    def ready(self, **kwargs):
        return self.wait_for(lambda: (r if (r := self.get(**kwargs))['available'] else None))

    def advance(self, seconds=31):
        self.tick += seconds
        with self.cache.condition:
            self.cache.condition.notify_all()

    def test_cold_get_does_not_query_or_acquire_the_primary_database_lock(self):
        finished = threading.Event()
        result = []
        def request():
            result.append(self.get())
            finished.set()
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=AssertionError('SQL in request')):
            with self.db.lock:
                thread = threading.Thread(target=request)
                thread.start()
                completed = finished.wait(1)
            thread.join(timeout=2)
        self.assertTrue(completed, 'Snapshot request waited on the ingestion connection lock')
        self.assertFalse(result[0]['available'])
        self.assertEqual(result[0]['status'], 'pending')
        self.assertIsNone(result[0]['flows'], 'Uncomputed counts must not become zero')

    def test_slow_worker_does_not_block_overview_ingestion_or_duplicate_requests(self):
        self.add()
        entered, release = threading.Event(), threading.Event()
        original = backend.EventDB.compute_network_summary
        calls = []
        def blocked(conn, start, end):
            calls.append(conn)
            conn.execute('SELECT COUNT(*) FROM events').fetchone()
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Test gate was not released')
            return original(conn, start, end)
        app = backend.App.__new__(backend.App)
        app.db, app.network = self.db, self.cache
        app.store = types.SimpleNamespace(ingest=lambda: None, offset=0, events=[], last_error='')
        app.sys = types.SimpleNamespace(**{name: lambda: {} for name in
            ('service', 'counters', 'ruleset', 'queue', 'current_rates', 'reload_state','telemetry')})
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=blocked):
            self.cache.start()
            self.assertTrue(entered.wait(2))
            completed, results = threading.Event(), []
            def request():
                for _ in range(8):
                    results.append(app.overview())
                self.add(self.stamp + 1)
                completed.set()
            thread = threading.Thread(target=request)
            thread.start()
            try:
                self.assertTrue(completed.wait(2), 'Network SQL blocked overview or ingestion')
                self.assertTrue(all(not r['network']['available'] for r in results))
                self.assertTrue(all('security' in r and 'series' in r for r in results))
            finally:
                release.set()
                thread.join(timeout=5)
            result = self.ready()
            self.assertEqual(result['flows'], 1, 'All aggregates must share the pre-write read snapshot')
            self.assertEqual(len(calls), 1, 'Identical REST/SSE ranges triggered duplicate SQL')
            self.assertIsNot(calls[0], self.db.conn)
            self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], 2)

    def test_default_is_prewarmed_without_a_page_request_and_refreshes_periodically(self):
        self.add()
        completed = threading.Event()
        original = backend.EventDB.compute_network_summary
        def observed(*args):
            value = original(*args)
            completed.set()
            return value
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=observed):
            self.cache.start()
            self.assertTrue(completed.wait(2), 'Default window was not prewarmed')
            first = self.ready()
            self.assertEqual((first['flows'], first['bytes'], first['addresses']), (1, 300, 2))
            self.assertEqual(first['status'], 'ready')
            self.add(self.stamp + 1)
            self.assertEqual(self.get()['flows'], 1)
            self.advance()
            refreshed = self.wait_for(lambda: (r if (r := self.get())['flows'] == 2 else None))
            self.assertGreaterEqual(refreshed['computed_at'], first['computed_at'])

    def test_custom_ranges_are_exact_and_do_not_reuse_other_ranges(self):
        stamp = int(self.stamp)
        self.add(stamp)
        a = dict(start=stamp - 1, end=stamp + 1, rolling=False)
        b = dict(start=stamp + 2, end=stamp + 3, rolling=False)
        self.assertFalse(self.get(**a)['available'])
        self.cache.start()
        first = self.ready(**a)
        self.assertEqual((first['flows'], first['range']), (1, [a['start'], a['end']]))
        self.assertFalse(self.get(**b)['available'])
        second = self.ready(**b)
        self.assertEqual((second['flows'], second['range']), (0, [b['start'], b['end']]))
        self.assertEqual(self.get(**a)['flows'], 1)

    def test_rolling_and_fixed_start_keys_reuse_only_their_own_window(self):
        self.cache.start()
        first = self.ready()
        high = backend.now() + 10
        shifted = self.get(start=high - 86400, end=high)
        self.assertEqual(shifted['range'], first['range'])
        self.assertFalse(self.get(start=high - 3600, end=high)['available'])
        since = dict(start=self.stamp - 5, rolling='fixed_start')
        self.get(**since)
        a = self.ready(**since)
        b = self.get(start=since['start'], end=high, rolling='fixed_start')
        self.assertEqual(a['range'], b['range'])
        self.assertFalse(self.get(start=since['start'] + 1, rolling='fixed_start')['available'])

    def test_filters_have_isolated_background_snapshots(self):
        self.add()
        self.cache.start()
        self.assertEqual(self.ready()['flows'],1)
        high=backend.now();low=high-86400
        matching=backend.App._overview_push({'app':'tls'})
        empty=backend.App._overview_push({'app':'http'})
        self.assertFalse(self.cache.get(low,high,True,push=empty)['available'])
        a=self.wait_for(lambda: (r if (r:=self.cache.get(low,high,True,push=matching))['available'] else None))
        b=self.wait_for(lambda: (r if (r:=self.cache.get(low,high,True,push=empty))['available'] else None))
        self.assertEqual((a['flows'],b['flows'],self.get()['flows']),(1,0,1))
        for i in range(20):self.cache.get(low,high,True,push=(['src=?'],[str(i)]))
        self.assertLessEqual(len(self.cache.entries),self.cache.MAX_ENTRIES)

    def test_failed_refresh_retains_success_beyond_freshness_limit_then_recovers(self):
        self.add()
        self.cache.start()
        first = self.ready()
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=sqlite3.OperationalError('fixture error')):
            self.advance()
            failed = self.wait_for(lambda: (r if (r := self.get())['error'] else None))
            self.assertTrue(failed['available'])
            self.assertEqual((failed['status'], failed['flows']), ('stale', 1))
            self.assertEqual(failed['computed_at'], first['computed_at'])
            self.advance(self.cache.MAX_AGE_SECONDS + 1)
            expired = self.get()
            self.assertTrue(expired['available'])
            self.assertEqual((expired['status'],expired['flows']),('stale',1))
            self.assertEqual(expired['computed_at'],first['computed_at'])
        self.advance()
        self.wait_for(lambda: self.get()['status'] == 'ready')

    def test_retry_is_bounded_and_does_not_discard_another_range_or_filter(self):
        with mock.patch.object(backend.EventDB,'compute_network_summary',side_effect=TimeoutError('fixture timeout')) as call:
            self.cache.start()
            self.wait_for(lambda:self.get()['status']=='error')
            first=self.get();self.assertGreater(first['retry_seconds'],0)
            for _ in range(20):self.get()
            self.assertEqual(call.call_count,1)
            self.advance(5)
            self.wait_for(lambda:call.call_count==2)
            self.wait_for(lambda:self.get()['retry_seconds']>5)
            self.assertFalse(self.get(start=self.stamp-1,end=self.stamp+1,rolling=False)['available'])

    def test_network_background_never_borrows_foreground_sql_helpers(self):
        self.add();self.db.query_pool=mock.Mock()
        result=self.cache._compute(self.cache.DEFAULT_KEY,self.db.network_generation)
        self.assertEqual(result['flows'],1)
        self.db.query_pool.snapshot.assert_not_called()

    def test_initial_failure_reports_unavailable_instead_of_empty_counts(self):
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=RuntimeError('fixture error')):
            self.cache.start()
            failed = self.wait_for(lambda: (r if (r := self.get())['status'] == 'error' else None))
            self.assertFalse(failed['available'])
            self.assertIsNone(failed['records'])
            self.assertIn('fixture error', failed['error'])

    def test_database_clear_discards_cached_and_inflight_results(self):
        self.add()
        captured, release = threading.Event(), threading.Event()
        original = backend.EventDB.compute_network_summary
        calls = []
        def blocked(*args):
            value = original(*args)
            calls.append(value)
            if len(calls) == 1:
                captured.set()
                release.wait(5)
            return value
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=blocked):
            self.cache.start()
            self.assertTrue(captured.wait(2))
            cleared = []
            thread = threading.Thread(target=lambda: cleared.append(self.db.clear()))
            thread.start()
            try:
                self.wait_for(lambda: self.db.network_generation > 0)
                self.assertFalse(self.get()['available'])
            finally:
                release.set()
                thread.join(timeout=5)
            self.assertEqual(cleared, [True])
            self.advance()
            self.assertEqual(self.ready()['flows'], 0)
            self.assertEqual(calls[0]['flows'], 1)

    def test_readonly_worker_cannot_write_even_if_query_only_is_disabled(self):
        original = backend.EventDB.compute_network_summary
        def checked(conn, start, end):
            self.assertEqual(conn.execute('PRAGMA query_only').fetchone()[0], 1)
            conn.execute('PRAGMA query_only=OFF')
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute('DELETE FROM events')
            conn.execute('PRAGMA query_only=ON')
            return original(conn, start, end)
        self.add()
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=checked):
            self.cache.start()
            self.assertEqual(self.ready()['flows'], 1)

    def test_query_deadline_interrupts_expensive_sql(self):
        self.cache.QUERY_SECONDS = .02
        def expensive(conn, *_):
            conn.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT SUM(x) FROM n').fetchone()
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=expensive):
            self.cache.start()
            failed = self.wait_for(lambda: (r if (r := self.get())['status'] == 'error' else None))
            self.assertIn('超时', failed['error'])
            self.assertFalse(failed['available'])

    def test_cache_and_pending_work_are_bounded_and_default_is_not_evicted(self):
        for index in range(30):
            self.cache.get(self.stamp + index, self.stamp + index + 1)
        self.assertLessEqual(len(self.cache.entries), self.cache.MAX_ENTRIES)
        self.assertIn(self.cache.DEFAULT_KEY, self.cache.entries)

    def test_inactive_custom_ranges_stop_refreshing_while_default_keeps_running(self):
        bounds = dict(start=int(self.stamp) - 1, end=int(self.stamp) + 2, rolling=False)
        original = backend.EventDB.compute_network_summary
        calls = []
        def counted(conn, start, end):
            calls.append('custom' if [start, end] == [bounds['start'], bounds['end']] else 'default')
            return original(conn, start, end)
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=counted):
            self.get(**bounds)
            self.cache.start()
            self.ready(**bounds)
            # Advance the fake clock only after both initial snapshots are published.
            self.ready()
            self.assertEqual(calls.count('custom'), 1)
            self.advance(self.cache.IDLE_SECONDS + 1)
            self.wait_for(lambda: calls.count('default') >= 2)
            self.assertEqual(calls.count('custom'), 1)

    def test_shutdown_interrupts_an_active_query_and_releases_its_connection(self):
        started = threading.Event()
        def expensive(conn, *_):
            started.set()
            conn.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT SUM(x) FROM n').fetchone()
        with mock.patch.object(backend.EventDB, 'compute_network_summary', side_effect=expensive):
            self.cache.start()
            self.assertTrue(started.wait(2))
            self.cache.close()
            self.assertFalse(self.cache.thread.is_alive())
            self.assertIsNone(self.cache.connection)


if __name__ == '__main__':
    unittest.main()
