"""Durable stream progress and cooperative background IO on synthetic events."""
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from event_processing import backend

m = backend()


class IngestResumeCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stream = self.root/'events.json'
        self.db = m.EventDB(str(self.root/'events.db'))

    def tearDown(self):
        self.db.conn.close()
        self.temp.cleanup()

    def line(self, index):
        return (json.dumps(dict(engine='snort3', epoch='fixture', kind='dns',
            data=dict(ts=1700000000 + index, uid=index + 1, trans_id=index,
                      query='fixture.example.test'))) + '\n').encode()

    def store(self):
        store = m.EventStore(str(self.stream), initial_tail=1)
        store.db = self.db
        return store

    def prime(self):
        self.stream.write_bytes(self.line(0))
        store = self.store();store.initial_tail = 4 << 20
        store.ingest()
        return store

    def count(self):
        return self.db.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]

    def test_new_database_enables_incremental_vacuum_and_reclaims_pages(self):
        self.assertEqual(self.db.conn.execute('PRAGMA auto_vacuum').fetchone()[0], 2)
        self.db.conn.execute('CREATE TABLE vacuum_fixture(payload BLOB)')
        self.db.conn.executemany('INSERT INTO vacuum_fixture VALUES(zeroblob(8192))', [()] * 32)
        self.db.conn.commit()
        self.db.conn.execute('DROP TABLE vacuum_fixture'); self.db.conn.commit()
        free = self.db.conn.execute('PRAGMA freelist_count').fetchone()[0]
        self.assertGreater(free, 0)
        self.db.conn.execute('PRAGMA incremental_vacuum(2000)').fetchall()
        self.db.conn.commit()
        self.assertLess(self.db.conn.execute('PRAGMA freelist_count').fetchone()[0], free)

    def test_existing_non_vacuum_database_is_not_rebuilt_on_open(self):
        path = self.root/'legacy.db'
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE preserved(value TEXT)')
        conn.execute("INSERT INTO preserved VALUES('fixture')"); conn.commit(); conn.close()
        legacy = m.EventDB(str(path))
        try:
            self.assertEqual(legacy.conn.execute('PRAGMA auto_vacuum').fetchone()[0], 0)
            self.assertEqual(legacy.conn.execute('SELECT value FROM preserved').fetchone()[0], 'fixture')
        finally:legacy.conn.close()

    def test_unrelated_unique_conflict_preserves_batch_and_durable_cursor(self):
        store = self.prime()
        old = dict(self.db.stream_cursor)
        # Models an older or externally supplied schema with a narrower identity.
        self.db.conn.execute('CREATE UNIQUE INDEX legacy_identity ON events(type)')
        self.db.conn.commit()
        with self.stream.open('ab') as output:output.write(self.line(1))
        store.last_ingest = 0; store.ingest()
        self.assertEqual(self.db.stream_cursor, old, 'A rejected row must never advance durable progress')
        self.assertTrue(self.db.write_error)
        self.assertEqual(len(self.db.buf), 1)
        self.assertIsNotNone(self.db.pending_cursor)
        self.db.conn.execute('DROP INDEX legacy_identity'); self.db.conn.commit()
        self.db.flush()
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.db.stream_cursor['offset'], self.stream.stat().st_size)
        self.assertFalse(self.db.write_error)

    def test_exact_replay_remains_idempotent_with_targeted_conflict_handling(self):
        store = self.prime()
        with self.stream.open('ab') as output:output.write(self.line(0) + self.line(1))
        store.last_ingest = 0; store.ingest()
        self.assertEqual(self.count(), 2)
        self.assertFalse(self.db.write_error)
        self.assertEqual(self.db.stream_cursor['offset'], self.stream.stat().st_size)

    def test_integer_binding_overflow_rolls_back_and_preserves_the_whole_batch(self):
        self.prime()
        old = dict(self.db.stream_cursor)
        for index in (1, 2):
            rec, raw = m.EventStore._parse(self.line(index).rstrip(b'\n'))
            self.db.add(rec, raw.decode())
        port = self.db.names.index('sport')
        self.db.buf[-1][port] = 2**63
        self.db.pending_cursor = dict(old, offset=old['offset'] + len(self.line(1)) + len(self.line(2)))
        self.db.flush()
        self.assertEqual(self.count(), 1)
        self.assertFalse(self.db.conn.in_transaction)
        self.assertEqual(len(self.db.buf), 2)
        self.assertTrue(self.db.write_error)
        self.assertEqual(self.db.stream_cursor, old)
        self.db.buf[-1][port] = 443
        self.db.flush()
        self.assertEqual(self.count(), 3)
        self.assertFalse(self.db.write_error)

    def test_restart_resumes_beyond_tail_limit_and_keeps_partial_record(self):
        self.prime()
        first = self.db.stream_cursor['offset']
        with self.stream.open('ab') as output:
            output.write(self.line(1) + self.line(2)[:40])
        self.db.conn.close();self.db = m.EventDB(str(self.root/'events.db'))
        store = self.store();store.ingest()
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.db.stream_cursor['offset'], first + len(self.line(1)))
        with self.stream.open('ab') as output:output.write(self.line(2)[40:])
        restarted = self.store();restarted.ingest()
        self.assertEqual(self.count(), 3)
        self.assertEqual(self.db.stream_cursor['offset'], self.stream.stat().st_size)

    def test_failed_commit_does_not_publish_checkpoint_and_retries_rows(self):
        store = self.prime()
        old = dict(self.db.stream_cursor)
        with self.stream.open('ab') as output:output.write(self.line(1))
        real = self.db.conn
        failed = mock.Mock(wraps=real)
        failed.commit.side_effect = sqlite3.OperationalError('fixture commit failure')
        self.db.conn = failed
        try:
            store.last_ingest = 0;store.ingest()
            self.assertEqual(self.db.stream_cursor, old)
            self.assertIsNotNone(self.db.pending_cursor)
            self.assertEqual(self.count(), 1)
        finally:self.db.conn = real
        self.db.flush()
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.db.stream_cursor['offset'], self.stream.stat().st_size)
        self.assertIsNone(self.db.pending_cursor)

    def test_legacy_resume_uses_first_anchor_and_keeps_late_timestamp(self):
        self.prime()
        self.db.conn.execute("DELETE FROM event_state WHERE key='stream_cursor'")
        self.db.conn.commit();self.db.stream_cursor = None
        with self.stream.open('ab') as output:
            output.write(self.line(-1) + self.line(0) + self.line(1))
        self.store().ingest()
        self.assertEqual(self.count(), 3)

    def test_copytruncate_regrowth_rejects_old_cursor(self):
        self.prime()
        self.stream.write_bytes(self.line(2) + self.line(3))
        self.store().ingest()
        self.assertEqual(self.count(), 3)

    def test_legacy_anchor_can_cross_a_read_boundary(self):
        self.prime()
        self.db.stream_cursor = None
        padding = b'x\n' * ((4 << 20) // 2 - 10)
        self.stream.write_bytes(padding + self.line(0) + self.line(1))
        self.assertEqual(self.store()._starting_offset(self.stream.stat()), len(padding) + len(self.line(0)))

    def test_clear_at_empty_file_keeps_all_subsequent_backlog(self):
        self.stream.touch();info = self.stream.stat()
        self.assertTrue(self.db.clear(dict(device=info.st_dev, inode=info.st_ino, offset=0)))
        self.stream.write_bytes(self.line(0) + self.line(1))
        self.store().ingest()
        self.assertEqual(self.count(), 2)

    def test_statistics_wait_for_ingestion_and_shutdown_wakes_wait(self):
        stats = m.StoredNetworkStats(self.db)
        busy = threading.Event();busy.set()
        self.db.background_busy = busy.is_set
        done = threading.Event()
        thread = threading.Thread(target=lambda: (stats._wait_for_ingest(), done.set()))
        thread.start()
        self.assertFalse(done.wait(.05))
        busy.clear()
        self.assertTrue(done.wait(2));thread.join()
        busy.set();stats.stop.set()
        with self.assertRaises(InterruptedError):stats._wait_for_ingest()

    def test_background_log_ranges_match_one_hour_ui_defaults(self):
        for name in ('hunt','incidents','events'):
            self.assertEqual(m.DataService.FIRST_PAGES[name]['window'], '60')


if __name__ == '__main__':
    unittest.main()
