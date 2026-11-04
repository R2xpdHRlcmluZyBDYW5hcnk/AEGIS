"""Clearing consumed raw bytes must preserve unread events and a live writer."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import sqlite3
import json
from unittest import mock
from contextlib import closing
import io

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name=='posix','Linux hole punching')
class NativeLogCleanupCase(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('native_log_cleanup',ROOT/'cleanup-native-logs.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'native'

    def test_consumed_prefix_is_removed_while_unread_tail_and_writer_position_survive(self):
        old=b'old complete\n';unread=b'unread complete\n';future=b'future complete\n'
        with self.path.open('wb') as writer:
            writer.write(old+unread);writer.flush()
            state=dict(inode=self.path.stat().st_ino,offset=len(old),tail_hash=hashlib.sha256(old).hexdigest())
            self.assertTrue(self.m.punch_consumed(self.path,state))
            self.assertEqual(self.path.read_bytes(),b'\0'*len(old)+unread)
            writer.write(future);writer.flush()
        self.assertEqual(self.path.read_bytes(),b'\0'*len(old)+unread+future)

    def test_changed_log_is_not_cleared_using_a_stale_checkpoint(self):
        self.path.write_bytes(b'unread data\n')
        state=dict(inode=self.path.stat().st_ino,offset=4,tail_hash='old digest')
        self.assertFalse(self.m.punch_consumed(self.path,state))
        self.assertEqual(self.path.read_bytes(),b'unread data\n')

    def test_full_boundary_preserves_writer_and_marks_partial_record_for_discard(self):
        with self.path.open('wb') as writer:
            writer.write(b'old complete\npartial');writer.flush()
            state=self.m.punch_boundary(self.path)
            self.assertTrue(state['discarding'])
            writer.write(b' old suffix\nnew complete\n');writer.flush()
        self.assertEqual(self.path.read_bytes(),b'\0'*state['offset']+b' old suffix\nnew complete\n')
        self.assertEqual(hashlib.sha256(b'\0'*state['offset']).hexdigest(),state['tail_hash'])

    def test_stream_replacement_keeps_database_rows_and_clear_epoch(self):
        database=self.path.with_name('events.db');self.path.write_bytes(b'old events\n')
        old=self.path.stat().st_ino
        with closing(sqlite3.connect(database)) as conn,conn:
            conn.executescript('CREATE TABLE event_state(key TEXT PRIMARY KEY,value TEXT);CREATE TABLE events(id INTEGER PRIMARY KEY,record TEXT);')
            conn.execute('INSERT INTO events VALUES(1,?)',('keep',))
            conn.execute('INSERT INTO event_state VALUES(?,?)',('clear_epoch','preserve'))
        cutoff=self.m.replace_stream(self.path,database)
        self.assertNotEqual(old,self.path.stat().st_ino);self.assertEqual(self.path.read_bytes(),b'')
        with closing(sqlite3.connect(database)) as conn,conn:
            self.assertEqual(conn.execute('SELECT * FROM events').fetchall(),[(1,'keep')])
            state=dict(conn.execute('SELECT * FROM event_state'))
        self.assertEqual(state['clear_epoch'],'preserve');self.assertEqual(json.loads(state['stream_cutoff']),cutoff)

    def test_consumers_are_restored_when_native_cleanup_fails(self):
        checkpoint=self.path.with_name('offsets.json');checkpoint.write_text('{"files":{}}')
        instance=self.path.with_name('instance.json');instance.write_text('{"epoch":"test"}')
        with mock.patch.object(self.m,'CHECKPOINT',checkpoint),mock.patch.object(self.m,'NATIVE',self.path.parent), \
                mock.patch.object(self.m.Path,'read_text',side_effect=lambda *a,**k:'{"files":{},"epoch":"test"}'), \
                mock.patch.object(self.m,'wait_web'),mock.patch.object(self.m,'replace_stream',side_effect=RuntimeError('fixture')), \
                mock.patch.object(self.m.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):self.m.clear_all()
        calls=[call.args[0] for call in run.call_args_list]
        self.assertIn(['systemctl','start','ips-web'],calls)
        self.assertIn(['systemctl','start','ips-event-bridge'],calls)

    def test_health_check_respects_configured_bind_address(self):
        config=self.path.with_name('config.json');config.write_text('{"bind":"192.0.2.1","port":9000}')
        opener=mock.Mock();opener.open.return_value=io.BytesIO(b'{"ok":true,"ingest_lag_bytes":0}')
        with mock.patch.object(self.m,'CONFIG',config),mock.patch.object(self.m.urllib.request,'build_opener',return_value=opener):
            self.m.wait_web(drained=True)
        opener.open.assert_called_once_with('http://192.0.2.1:9000/healthz',timeout=2)


if __name__=='__main__':unittest.main()
