"""Actual spawned CPU workers, bounded queues and consistent concurrent SQL reads."""
import hashlib
import json
import os
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from parallel_cpu import CPUExecutor, byte_batches
from parallel_sql import ReadExecutor
from event_processing import backend
from rule_inventory import parse, parse_parallel
import snort_rules
import snort_engine


def hash_work(index):
    value = str(index).encode()
    for _ in range(20000):
        value = hashlib.sha256(value).digest()
    return index, value


def abort_worker(_):
    os._exit(3)


class CPUCase(unittest.TestCase):
    def test_spawned_workers_preserve_results_and_order(self):
        pool = CPUExecutor(4)
        try:
            stats = {}
            rows = list(pool.ordered(hash_work,range(16),stats))
            self.assertEqual(rows,[hash_work(i) for i in range(16)])
            if pool.workers>1:
                self.assertGreater(len(stats['pids']),1)
        finally:
            pool.close()
        with self.assertRaises(RuntimeError):
            list(pool.ordered(hash_work,[0]))

    def test_batch_boundary_and_oversized_single_item(self):
        self.assertEqual(list(byte_batches([b'12',b'34',b'56789',b'x'],budget=4)),
                         [[b'12',b'34'],[b'56789'],[b'x']])

    def test_failed_process_pool_is_replaced_for_the_next_batch(self):
        pool=CPUExecutor(4)
        try:
            if pool.workers<2:self.skipTest('Single CPU direct execution has no child process')
            with self.assertRaises(BrokenProcessPool):list(pool.ordered(abort_worker,[0]))
            self.assertEqual(list(pool.ordered(hash_work,[1,2])),[hash_work(1),hash_work(2)])
        finally:pool.close()

    def test_rule_batches_preserve_continuations_and_record_order(self):
        raw=('alert tcp any any -> any any (msg:"unicode 测试 \\\" quote"; \\\n sid:498; rev:1;)\n'*18000).encode()
        pool=CPUExecutor(4)
        try:
            self.assertEqual(parse_parallel(raw,pool),parse(raw))
        finally:pool.close()

    def test_metadata_batches_preserve_grades_and_last_rule_precedence(self):
        lines=['alert ip any any -> any any (msg:"fixture"; sid:%d; priority:%d; classtype:test; metadata:mitre_tactic_id TA0001;)\n'%(i%4000,i%3+1) for i in range(20000)]
        classifications={'test':2};expected=snort_engine._metadata_lines((lines,classifications))
        pool=CPUExecutor(4)
        try:
            actual={}
            for rows in pool.ordered(snort_engine._metadata_lines,((batch,classifications) for batch in byte_batches(lines,size=len))):
                actual.update(rows)
            self.assertEqual(actual,expected)
        finally:pool.close()

    def test_ingestion_parallel_values_equal_serial_values_and_retry_is_atomic(self):
        module=backend();pool=CPUExecutor(4)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);stream=root/'events.json'
                stream.write_text(''.join(json.dumps(dict(engine='snort3',epoch='fixture',kind='dns',data=dict(
                    ts=1700000000+i/1000,uid=2**63+i,trans_id=i,query='x'*180+'.example.test')))+'\n' for i in range(2048)))
                databases=[]
                try:
                    stores=[]
                    for name,parallel in [('serial',False),('parallel',True)]:
                        db=module.EventDB(str(root/(name+'.db')));databases.append(db)
                        store=module.EventStore(str(stream),initial_tail=4<<20)
                        store.db=db
                        if parallel:store.cpu=pool
                        store.ingest();db.flush();stores.append(store)
                    serial,parallel=databases
                    columns=','.join(serial.names)
                    self.assertEqual(serial.conn.execute('SELECT '+columns+' FROM events ORDER BY id').fetchall(),
                                     parallel.conn.execute('SELECT '+columns+' FROM events ORDER BY id').fetchall())
                    self.assertEqual(stores[0].offset,stores[1].offset)
                    failed=module.EventStore(str(stream),initial_tail=4<<20)
                    failed.db=serial;failed.cpu=mock.Mock()
                    failed.cpu.ordered.side_effect=RuntimeError('worker failed')
                    with self.assertRaisesRegex(RuntimeError,'worker failed'):failed.ingest()
                    self.assertEqual(failed.offset,0)
                    self.assertFalse(failed.events)
                finally:
                    for db in databases:db.conn.close()
        finally:pool.close()


class SQLCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/'events.db'
        self.writer = sqlite3.connect(self.path)
        self.writer.execute('PRAGMA journal_mode=WAL')
        self.writer.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,value INTEGER)')
        self.writer.execute('INSERT INTO events VALUES(1,10)')
        self.writer.commit()
        self.source = types.SimpleNamespace(path=self.path,lock=threading.RLock())
        self.reader = sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True)
        self.pool = ReadExecutor()

    def tearDown(self):
        self.pool.close()
        self.reader.close()
        self.writer.close()
        self.temp.cleanup()

    def test_four_queries_execute_together_on_one_snapshot(self):
        gate = threading.Barrier(4)
        seen = set()
        lock = threading.Lock()
        def hold(value):
            with lock:
                seen.add(threading.get_ident())
            gate.wait(timeout=3)
            return value
        setup=lambda conn:conn.create_function('hold',1,hold)
        setup(self.reader)
        with self.pool.snapshot(self.source,self.reader,setup=setup) as group:
            self.writer.execute('INSERT INTO events VALUES(2,20)')
            self.writer.commit()
            result = group.fetch([('SELECT hold(COUNT(*)) FROM events',())]*4)
        self.assertEqual(result,[[(1,)]]*4,'All reads must precede the concurrent commit')
        self.assertEqual(len(seen),4)

    def test_busy_helpers_leave_another_query_available(self):
        other = sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True)
        try:
            with self.pool.snapshot(self.source,self.reader) as first:
                with self.pool.snapshot(self.source,other) as second:
                    self.assertEqual(len(first.members),3)
                    self.assertEqual(second.members,[])
                    self.assertEqual(second.fetch([('SELECT value FROM events',())]),[[(10,)]])
        finally:
            other.close()

    def test_cancellation_interrupts_helper_sql(self):
        cancelled=threading.Event()
        timer=threading.Timer(.1,cancelled.set)
        with self.pool.snapshot(self.source,self.reader,cancelled=cancelled.is_set) as group:
            timer.start()
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError,'interrupted'):
                    group.fetch([('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT SUM(x) FROM n',())])
            finally:timer.join()

    def test_helper_read_has_no_elapsed_time_deadline(self):
        with self.pool.snapshot(self.source,self.reader) as group:
            clock = time.monotonic
            with mock.patch.object(time,'monotonic',side_effect=lambda:clock()+86400):
                self.assertEqual(group.fetch([('SELECT value FROM events',())]),[[(10,)]])

    def test_worker_start_failure_releases_all_reserved_slots(self):
        with mock.patch.object(self.pool.executor,'submit',side_effect=RuntimeError('start failed')):
            with self.assertRaisesRegex(RuntimeError,'start failed'):
                with self.pool.snapshot(self.source,self.reader):pass
        for _ in range(3):self.assertTrue(self.pool.slots.acquire(blocking=False))
        self.assertFalse(self.pool.slots.acquire(blocking=False))
        for _ in range(3):self.pool.slots.release()


class QueryCase(unittest.TestCase):
    def setUp(self):
        self.module=backend();self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.db=self.module.EventDB(str(self.root/'events.db'));self.cpu=CPUExecutor(4)
        self.addCleanup(self.db.conn.close);self.addCleanup(self.cpu.close)
        self.store=self.module.EventStore(str(self.root/'events.json'),initial_tail=4<<20)
        self.store.db=self.db
        self.app=object.__new__(self.module.App)
        self.app.db,self.app.store=self.db,self.store
        self.stamp=self.module.now()-60
        events=[]
        for i in range(1024):
            event=dict(timestamp=self.module.iso(self.stamp+i/1000),event_type='alert',
                src_ip='192.0.2.1',dest_ip='198.51.100.1',proto='TCP',
                alert=dict(signature='fixture '+str(i),signature_id=1000+i,severity=1,
                           metadata={'mitre_tactic_id':['TA0001' if i%2 else 'TA0002']}))
            raw=json.dumps(event);events.append(raw+'\n')
            self.db.add(self.module.EventStore._parse(raw.encode())[0],raw)
        (self.root/'events.json').write_text(''.join(events))
        self.db.flush();self.store.ingest()

    def test_metadata_process_filter_equals_sql_for_booleans_and_pagination(self):
        queries=('mitre_tactic_id:TA0001','NOT mitre_tactic_id:*',
                 'mitre_tactic_id:TA0002 OR sid:1001',
                 'type:alert AND NOT mitre_tactic_id:TA0001')
        for query in queries:
            params=dict(q=query,source='db',limit='7',offset='5',view='list',
                        **{'from':str(self.stamp-1),'to':str(self.stamp+2)})
            self.db.cpu=None
            expected=self.app.hunt(params)
            self.db.cpu=self.cpu
            actual=self.app.hunt(params)
            self.assertEqual(actual,expected,query)

    def test_file_and_memory_parallel_filters_equal_serial(self):
        query='sid:>1500 AND NOT mitre_tactic_id:TA0001'
        node=self.module.hunt_parse(query);matcher=lambda rec:self.module.hunt_match(node,rec,False)
        for name in ('query','search_history'):
            method=getattr(self.store,name)
            self.store.cpu=None
            expected=method(window=60,matcher=matcher,limit=9,offset=3)
            self.store.cpu=self.cpu
            actual=method(window=60,matcher=matcher,matcher_spec=(node,False),limit=9,offset=3)
            self.assertEqual(actual,expected,name)

    def test_sql_parallel_summary_incidents_and_pages_equal_serial(self):
        self.app.config={'read_workers':4}
        cache=self.module.SharedCache(1<<20)
        service=self.module.DataService(self.app,cache)
        try:
            low,high=self.stamp-1,self.stamp+2
            expected=(self.db.security_summary(start=low,end=high,dedup=True),
                      self.db.security_incidents(low,high,limit=8),
                      self.db.search_range(low,high,limit=8,list_view=True))
            def query(reader):
                self.assertEqual(len(reader.db.parallel.members),3)
                return (reader.db.security_summary(start=low,end=high,dedup=True),
                        reader.db.security_incidents(low,high,limit=8),
                        reader.db.search_range(low,high,limit=8,list_view=True))
            self.assertEqual(service.execute(query),expected)
        finally:service.close()


class SourceCase(unittest.TestCase):
    def test_sources_run_concurrently_with_a_shared_budget_and_ordered_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);gate=threading.Barrier(2);limits=[]
            def candidate(data,config,source,settings,offline,program,custom,limit):
                limits.append(limit);gate.wait(timeout=2)
                sid=1 if source=='snort/community' else 2
                return 'alert ip any any -> any any (sid:%d;)\n'%sid
            with mock.patch.object(snort_rules,'enabled_sources',return_value={'snort/registered','snort/community'}),\
                 mock.patch.object(snort_rules,'worker_count',return_value=4),\
                 mock.patch.object(snort_rules,'update_one',side_effect=candidate):
                snort_rules.update(root,root/'config')
            text=(root/'rules/snort.rules').read_text()
            self.assertEqual(limits,[2,2])
            self.assertLess(text.index('sid:1'),text.index('sid:2'))


if __name__ == '__main__':
    unittest.main()
