"""Offline recovery never changes original evidence or claims complete salvage."""
from contextlib import closing
import importlib.util
import importlib.machinery
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recover_event_db', ROOT / 'recover-event-db.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / 'snapshot'
        self.original = self.snapshot / 'original'
        self.original.mkdir(parents=True)
        self.db = self.original / 'events.db'
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,ts NUMERIC,type TEXT,payload TEXT)')
            conn.executemany('INSERT INTO events VALUES(?,?,?,?)',
                             [(n, n + .125, 'flow', 'x' * 500) for n in range(1, 301)])
            conn.execute('CREATE INDEX events_ts ON events(ts)')
            conn.execute('CREATE TABLE settings(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT)')
            conn.execute("INSERT INTO settings(value) VALUES('preserved')")
            conn.commit()
        self.reference = self.root / 'reference.db'
        with closing(sqlite3.connect(self.reference)) as conn:
            conn.execute('CREATE TABLE expected(id INTEGER PRIMARY KEY,ts NUMERIC)')
            conn.executemany('INSERT INTO expected VALUES(?,?)', [(n, n + .125) for n in range(1, 301)])
            conn.commit()
        self.seal()

    def seal(self):
        (self.snapshot / 'snapshot.json').write_text(json.dumps({
            'database_path': '/var/lib/snort/events.db',
            'files': {'events.db': {'bytes': self.db.stat().st_size, 'sha256': m.digest(self.db)}}
        }), encoding='utf-8')

    def test_rejects_modified_snapshot_before_creating_candidate(self):
        with self.db.open('ab') as handle:
            handle.write(b'changed')
        output = self.root / 'candidate'
        with self.assertRaisesRegex(ValueError, 'checksum'):
            m.recover(self.snapshot, output, Path('unused'))
        self.assertFalse(output.exists())

    def test_rejects_unexpected_or_traversal_file(self):
        manifest = json.loads((self.snapshot / 'snapshot.json').read_text())
        manifest['files']['../other.db'] = {'bytes': 0, 'sha256': ''}
        (self.snapshot / 'snapshot.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'only the database'):
            m.read_snapshot(self.snapshot)

    def test_validation_reports_missing_extra_and_changed_identity(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('DELETE FROM events WHERE id=2')
            conn.execute('UPDATE events SET ts=0 WHERE id=3')
            conn.execute("INSERT INTO events VALUES(400,400,'flow','extra')")
            conn.commit()
        report = m.validate(self.db, self.reference)
        self.assertEqual(report['integrity_check'], ['ok'])
        self.assertEqual(report['identity_comparison'],
                         dict(expected=300, missing=1, unexpected=1, timestamp_mismatches=1))
        self.assertFalse(report['activation_performed'])
        self.assertFalse(report['completeness_proven'])

    def test_invalid_text_is_encoded_without_changing_its_bytes(self):
        statement = b"INSERT INTO 'events'('id','payload') VALUES(1,'a\x00\xff''b');\n"
        normalized = m.normalize_values(statement)
        with closing(sqlite3.connect(':memory:')) as conn:
            conn.execute('CREATE TABLE events(id,payload)')
            conn.execute(normalized.decode('ascii'))
            self.assertEqual(conn.execute('SELECT CAST(payload AS BLOB) FROM events').fetchone()[0], b"a\x00\xff'b")
        ordinary = b"INSERT INTO 'events'('id','payload') VALUES(1,X'001aff');\n"
        self.assertEqual(m.normalize_values(ordinary), ordinary)

    def test_stream_keeps_statement_boundaries_with_newlines_in_text(self):
        source = io.BytesIO(b".dbconfig defensive off\nBEGIN;\nINSERT INTO t VALUES('line\nnext\x1a');\nCOMMIT;\n")
        target = io.BytesIO()
        m.relay_recovery(source, target)
        self.assertIn(b'CAST(X\'6c696e650a6e6578741a\' AS TEXT)', target.getvalue())
        with self.assertRaisesRegex(ValueError, 'ended inside'):
            m.relay_recovery(io.BytesIO(b"INSERT INTO t VALUES('incomplete"), io.BytesIO())

    def test_index_cell_reader_matches_sqlite_index_values(self):
        path = self.root / 'keys.db'
        expected = {n: hashlib.sha256(str(n).encode()).hexdigest() for n in range(1, 301)}
        with closing(sqlite3.connect(path)) as conn:
            conn.execute('CREATE TABLE keys(id INTEGER PRIMARY KEY,event_key TEXT)')
            conn.executemany('INSERT INTO keys VALUES(?,?)', expected.items())
            conn.execute('CREATE INDEX keys_index ON keys(event_key)')
            conn.commit()
            page_size = conn.execute('PRAGMA page_size').fetchone()[0]
        wanted = {1, 128, 256, 300}
        found = {}
        with path.open('rb') as handle:
            for page in iter(lambda: handle.read(page_size), b''):
                found.update(m.index_key_candidates(page, wanted))
        self.assertEqual(found, {n: expected[n] for n in wanted})
        self.assertEqual(list(m.index_key_candidates(b'\x0a' + bytes(511), wanted)), [])

    def test_table_leaf_reader_preserves_sqlite_values(self):
        path = self.root / 'leaf.db'
        with closing(sqlite3.connect(path)) as conn:
            conn.execute('CREATE TABLE rows(id INTEGER PRIMARY KEY,n INTEGER,f REAL,t TEXT,b BLOB,z)')
            expected = {n: (n, -n, n + .125, '文本\0' + str(n), bytes([n % 256]), None) for n in range(1, 301)}
            conn.executemany('INSERT INTO rows VALUES(?,?,?,?,?,?)', expected.values())
            conn.commit()
            page_size = conn.execute('PRAGMA page_size').fetchone()[0]
        wanted = {1, 128, 256, 300}
        found = {}
        with path.open('rb') as handle:
            for page in iter(lambda: handle.read(page_size), b''):
                for identity, values in m.table_row_candidates(page, wanted):
                    values[0] = identity
                    found[identity] = tuple(values)
        self.assertEqual(found, {n: expected[n] for n in wanted})

    def test_wal_reader_checks_frames_and_commit_markers(self):
        path = self.root / 'wal.db'
        with closing(sqlite3.connect(path)) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA wal_autocheckpoint=0')
            conn.execute('CREATE TABLE rows(id INTEGER PRIMARY KEY,value TEXT)')
            conn.execute("INSERT INTO rows VALUES(123,'committed')")
            conn.commit()
            copy = self.root / 'saved.wal'
            copy.write_bytes(Path(str(path) + '-wal').read_bytes())
        stats = {}
        rows = list(m.committed_wal_rows(copy, {123}, stats))
        self.assertTrue(any(identity == 123 and values == [None, 'committed'] for _, identity, values in rows))
        self.assertGreater(stats['commits'], 0)
        historical_stats = {}
        historical = list(m.forensic_wal_rows(copy, {123}, historical_stats))
        self.assertTrue(any(identity == 123 and values == [None, 'committed'] for _, identity, values in historical))
        self.assertEqual(historical_stats['checksum_gaps'], 0)
        broken = bytearray(copy.read_bytes())
        broken[60] ^= 1
        copy.write_bytes(broken)
        stats = {}
        self.assertEqual(list(m.committed_wal_rows(copy, {123}, stats)), [])
        self.assertEqual(stats['stopped_reason'], 'checksum_mismatch')

    def test_cursor_replay_keeps_late_events_deduplicates_and_reserves_ids(self):
        loader = importlib.machinery.SourceFileLoader('recovery_test_backend', str(ROOT / 'ips-web'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        backend = importlib.util.module_from_spec(spec)
        loader.exec_module(backend)
        database = backend.EventDB(str(self.root / 'replay.db'))
        self.addCleanup(database.conn.close)
        def event(second):
            return json.dumps(dict(event_type='flow', timestamp='2026-10-31T00:00:%02d.123456+0000' % second,
                                   proto='TCP', flow={'state': 'closed'})).encode()
        first, last, late = event(10), event(20), event(15)
        for raw in (first, last):
            record, line = backend.EventStore._parse(raw)
            database.add(record, line.decode())
        database.flush()
        key, stamp = database.conn.execute('SELECT event_key,ts FROM events ORDER BY id DESC LIMIT 1').fetchone()
        eve = self.root / 'retained-eve.json'
        eve.write_bytes(first + b'\n' + last + b'\n' + late + b'\n' + first + b'\n' + b'{"partial":')
        offset = m.find_eve_cursor(backend, eve, key, stamp)
        report = m.replay_eve(backend, database.conn, eve, offset, 100)
        self.assertEqual(report['inserted'], 1)
        self.assertEqual(database.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], 3)
        self.assertEqual(database.conn.execute('SELECT id FROM events WHERE ts<? AND id>100', (stamp,)).fetchone()[0], 101)
        self.assertEqual(report['completed_offset'], len(first + b'\n' + last + b'\n' + late + b'\n' + first + b'\n'))

    def test_index_only_rebuild_preserves_every_table_and_sequence(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("INSERT INTO settings(id,value) VALUES(900,'sequence preserved')")
            conn.execute('DELETE FROM settings WHERE id=900')
            conn.execute("UPDATE events SET payload=CAST(X'610062ff' AS TEXT) WHERE id=1")
            conn.execute("UPDATE events SET payload=X'' WHERE id=2")
            conn.commit()
            size = conn.execute('PRAGMA page_size').fetchone()[0]
            page = conn.execute("SELECT rootpage FROM sqlite_schema WHERE name='events_ts'").fetchone()[0]
        with self.db.open('r+b') as handle:
            handle.seek((page - 1) * size)
            handle.write(b'\0')
        self.seal()
        original = m.digest(self.db)
        report = m.recover(self.snapshot, self.root / 'rebuilt',
                           Path('unused'), indexes_only=True)
        self.assertEqual(m.digest(self.db), original)
        self.assertTrue(report['all_table_values_preserved'])
        self.assertEqual(report['integrity_check'], ['ok'])
        with closing(sqlite3.connect(self.root / 'rebuilt/candidate.db')) as conn:
            self.assertEqual(conn.execute("SELECT seq FROM sqlite_sequence WHERE name='settings'").fetchone()[0], 900)
        self.assertEqual(report['table_counts']['events'], 300)

    def test_replay_rejects_non_identity_conflicts_and_rolls_back(self):
        from event_processing import backend
        module = backend()
        database = module.EventDB(str(self.root / 'conflict.db'))
        try:
            database.conn.execute('CREATE UNIQUE INDEX legacy_identity ON events(type)')
            database.conn.commit()
            eve = self.root / 'conflict.json'
            eve.write_text(''.join(json.dumps(dict(event_type='flow',
                timestamp='2026-10-31T00:00:%02d+0000' % second, proto='TCP')) + '\n'
                for second in (1, 2)))
            with self.assertRaises(sqlite3.IntegrityError):
                m.replay_eve(module, database.conn, eve, 0, 0)
            self.assertEqual(database.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], 0)
        finally:database.conn.close()

    def test_index_only_rebuild_rejects_unreadable_table(self):
        with closing(sqlite3.connect(self.db)) as conn:
            size = conn.execute('PRAGMA page_size').fetchone()[0]
            page = conn.execute("SELECT rootpage FROM sqlite_schema WHERE name='events'").fetchone()[0]
        with self.db.open('r+b') as handle:
            handle.seek((page - 1) * size)
            handle.write(b'\0')
        candidate = self.root / 'rejected.db'
        with self.assertRaises(sqlite3.DatabaseError):
            m.rebuild_indexes(self.db, candidate)
        self.assertFalse(candidate.exists())

    @unittest.skipUnless(os.environ.get('SQLITE_RECOVERY_CLI'), 'Set SQLITE_RECOVERY_CLI for CLI recovery regression')
    def test_real_recovery_keeps_originals_and_detects_lost_rows(self):
        with closing(sqlite3.connect(self.db)) as conn:
            page_size = conn.execute('PRAGMA page_size').fetchone()[0]
            leaf = conn.execute("SELECT rootpage FROM sqlite_schema WHERE name='events'").fetchone()[0]
        with self.db.open('r+b') as handle:
            while True:
                handle.seek((leaf - 1) * page_size)
                page = handle.read(page_size)
                if page[0] == 13:
                    break
                self.assertEqual(page[0], 5)
                offset = int.from_bytes(page[12:14], 'big')
                leaf = int.from_bytes(page[offset:offset + 4], 'big')
            handle.seek((leaf - 1) * page_size)
            handle.write(b'\0')
        self.seal()
        before = m.digest(self.db)
        report = m.recover(self.snapshot, self.root / 'recovered',
                           Path(os.environ['SQLITE_RECOVERY_CLI']), self.reference)
        self.assertEqual(m.digest(self.db), before)
        self.assertEqual(sorted(p.name for p in self.original.iterdir()), ['events.db'])
        self.assertEqual(report['integrity_check'], ['ok'])
        self.assertGreater(report['identity_comparison']['missing'], 0)
        self.assertEqual(report['table_counts']['settings'], 1)
        self.assertGreater(report['source_row_comparison']['unreadable'], 0)
        self.assertEqual(report['source_row_comparison']['mismatched'], 0)
        self.assertFalse(report['completeness_proven'])
        with self.assertRaises(FileExistsError):
            m.recover(self.snapshot, self.root / 'recovered', Path(os.environ['SQLITE_RECOVERY_CLI']))


if __name__ == '__main__':
    unittest.main()
