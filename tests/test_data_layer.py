"""Bounded shared data, lazy evidence and exact incremental projections."""
import concurrent.futures
import http.client
from http.server import BaseHTTPRequestHandler
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import random
import sqlite3
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('data_layer_backend',str(ROOT/'ips-web'))
spec = importlib.util.spec_from_loader(loader.name,loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


class DataLayerCase(unittest.TestCase):
    def test_slow_log_and_prefetch_leave_a_panel_slot_available(self):
        entered=threading.Event();background=threading.Event();release=threading.Event()
        connections=[]
        def log(reader,params):
            connections.append(reader.db.conn);entered.set();self.assertTrue(release.wait(3));return {'total':1}
        def prefetch(reader,params):
            connections.append(reader.db.conn);background.set();self.assertTrue(release.wait(3));return {'total':1}
        def overview(reader,params):
            connections.append(reader.db.conn);return {'panel':True}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            slow=pool.submit(self.service.query,log,{})
            warm=pool.submit(self.service.query,prefetch,{},background=True)
            try:
                self.assertTrue(entered.wait(2));self.assertTrue(background.wait(2))
                queued=pool.submit(self.service.query,log,{'offset':50})
                self.assertTrue(pool.submit(self.service.query,overview,{}).result(2)['panel'])
                self.assertFalse(queued.done(),'log concurrency must respect its lane limit')
                self.assertEqual(len({id(conn) for conn in connections}),3)
            finally:release.set()
            self.assertEqual(slow.result(3)['total'],1);self.assertEqual(warm.result(3)['total'],1)
            self.assertEqual(queued.result(3)['total'],1)

    def test_close_interrupts_sql_and_rejects_queued_and_new_reads(self):
        entered=threading.Event()
        def long_query(reader):
            entered.set()
            return reader.db.conn.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT SUM(x) FROM n').fetchone()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            running=pool.submit(self.service.execute,long_query)
            self.assertTrue(entered.wait(2))
            waiting=pool.submit(self.service.execute,lambda reader:{})
            self.service.close()
            with self.assertRaises(sqlite3.OperationalError):running.result(3)
            with self.assertRaisesRegex(RuntimeError,'关闭'):waiting.result(3)
        self.assertFalse(self.service.readers)
        self.service.schedule('after-close',lambda:None);self.assertFalse(self.service.queue)
        with self.assertRaisesRegex(RuntimeError,'关闭'):self.service.execute(lambda reader:{})
        self.assertTrue(self.service.slots.acquire(blocking=False));self.service.slots.release()

    def test_database_stats_uses_readonly_connection_without_ingestion_lock(self):
        self.add()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool,self.db.lock:
            result=pool.submit(self.app.database_stats).result(2)
        self.assertEqual(result['rows'],1)

    def test_clear_invalidates_already_running_security_responses(self):
        entered=threading.Event();release=threading.Event()
        def incidents(reader,params):
            entered.set();release.wait(3)
            return dict(incidents=[{'id':'deleted-session'}],total=1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            owner=pool.submit(self.service.query,incidents,{})
            self.assertTrue(entered.wait(2))
            waiter=threading.Event();event=next(iter(self.service.inflight.values()))['event'];wait=event.wait
            def wait_entered(timeout):waiter.set();return wait(timeout)
            with mock.patch.object(event,'wait',side_effect=wait_entered):
                follower=pool.submit(self.service.query,incidents,{})
                self.assertTrue(waiter.wait(2))
                self.app.clear_history();release.set()
                for future in (owner,follower):
                    with self.assertRaisesRegex(RuntimeError,'历史记录已变更'):future.result(timeout=5)

    def test_clear_resets_projection_and_memory_and_does_not_replay_deleted_stream_on_restart(self):
        raw=dict(timestamp=m.iso(self.stamp),event_type='flow',src_ip='192.0.2.1',dest_ip='198.51.100.2',proto='TCP',flow={})
        Path(self.app.store.path).write_text(json.dumps(raw)+'\n')
        self.app.store.ingest();self.db.flush();self.sync(initial=True)
        self.assertTrue(self.app.store.events)
        self.assertTrue(self.app.clear_history())
        self.assertFalse(self.app.store.events)
        self.add('flow',self.stamp+1)
        with mock.patch.object(self.stats,'_reconcile',side_effect=AssertionError('clear must reset projection directly')):
            self.sync()
        self.assertEqual(self.derived.execute('SELECT COUNT(*) FROM facts').fetchone()[0],1)
        self.assertEqual(self.stats.aggregate(self.derived,self.stamp-1,self.stamp+2)['flows'],1)
        restored=m.EventDB(self.db.path)
        store=m.EventStore(self.app.store.path);store.db=restored
        try:
            store.ingest();restored.flush()
            self.assertFalse(store.events)
            self.assertEqual(restored.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
            raw['timestamp']=m.iso(self.stamp+2)
            with Path(store.path).open('a') as output:output.write(json.dumps(raw)+'\n')
            store.last_ingest=0;store.ingest();restored.flush()
            self.assertEqual(len(store.events),1)
            recovered=m.StoredNetworkStats(restored)
            try:
                recovered.sync(restored.conn,self.derived,initial=True)
                self.assertEqual(recovered.aggregate(self.derived,self.stamp-1,self.stamp+3)['flows'],2)
            finally:recovered.close()
        finally:restored.conn.close()

    def test_projection_without_clear_marker_is_rebuilt_from_authoritative_events(self):
        self.add('flow');self.sync(initial=True)
        self.derived.execute("DELETE FROM meta WHERE k='clear_epoch'")
        self.derived.execute('UPDATE flows SET n=999')
        self.derived.commit()
        self.sync(initial=True)
        self.assertEqual(self.stats.aggregate(self.derived,self.stamp-1,self.stamp+1)['flows'],1)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = m.EventDB(str(self.root/'events.db'))
        self.cache = m.SharedCache(1<<20)
        self.app = m.App.__new__(m.App)
        self.app.config = {'read_workers':2}
        self.app.db = self.db
        self.app.store = m.EventStore(str(self.root/'eve.json'),memory_budget=64<<10)
        self.app.store.db = self.db
        self.service = m.DataService(self.app,self.cache)
        self.app.data = self.service
        self.stats = m.StoredNetworkStats(self.db)
        self.app.analytics = self.stats
        self.source = sqlite3.connect(Path(self.db.path).as_uri()+'?mode=ro',uri=True)
        self.source.execute('PRAGMA query_only=ON')
        self.derived = sqlite3.connect(self.stats.path)
        self.stats.install(self.derived)
        self.stamp = 1793491200

    def tearDown(self):
        self.service.close()
        self.stats.close()
        self.source.close()
        self.derived.close()
        self.db.conn.close()
        self.temp.cleanup()

    def add(self,kind='alert',ts=None,**extra):
        raw = dict(timestamp=m.datetime.fromtimestamp(self.stamp if ts is None else ts,m.timezone.utc).isoformat(timespec='microseconds'),event_type=kind,
                   src_ip='192.0.2.1',src_port=12345,dest_ip='198.51.100.2',dest_port=443,
                   proto='TCP',alert=dict(signature='Test',signature_id=10,severity=1,action='allowed'),
                   flow=dict(bytes_toserver=100,bytes_toclient=20,pkts_toserver=1,pkts_toclient=1))
        raw.update(extra)
        self.db.add(*m.EventStore._parse(json.dumps(raw)))
        self.db.flush()
        return raw

    def sync(self,initial=False,batch=1024):
        for _ in range(1000):
            if self.stats.sync(self.source,self.derived,initial,batch):
                return
            initial = False
        self.fail('backfill failed to finish')

    def test_response_lru_byte_limit_oversize_and_copy_isolation(self):
        cache = m.SharedCache(4096)
        for index in range(30):
            cache.put(str(index),{'data':'x'*450})
            self.assertLessEqual(cache.stats()['used_bytes'],4096)
        self.assertIsNone(cache.get('0'))
        data = cache.get('29');data['data']='changed'
        self.assertNotEqual(cache.get('29')['data'],'changed')
        self.assertFalse(cache.put('large',{'data':'x'*5000}))
        self.assertIsNone(cache.get('large'))

    def test_record_buffers_are_bounded_even_without_row_cap(self):
        records = m.BoundedRecords(100000,4096)
        records.extend({'raw':'x'*1000,'id':index} for index in range(100))
        self.assertLessEqual(records.bytes,4096)
        self.assertLess(len(records),100)
        records.clear();self.assertEqual(records.bytes,0)
        empty = m.BoundedRecords(0,1000);empty.append({});self.assertFalse(empty)

    def test_requests_coalesce_and_readonly_connection_does_not_wait_for_writer_lock(self):
        self.add()
        entered,release = threading.Event(),threading.Event()
        calls = []
        def producer(reader,params):
            calls.append(reader.db.conn)
            with self.assertRaises(sqlite3.OperationalError):
                reader.db.conn.execute('DELETE FROM events')
            entered.set();self.assertTrue(release.wait(3))
            return {'total':reader.db.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            with self.db.lock:
                futures = [pool.submit(self.service.query,producer,{}) for _ in range(6)]
                self.assertTrue(entered.wait(2),'request acquired ingestion lock')
                release.set()
                results = [future.result(3) for future in futures]
        self.assertEqual(len(calls),1)
        self.assertTrue(all(item['total']==1 for item in results))
        self.assertIsNot(calls[0],self.db.conn)

    def test_stale_snapshot_schedules_once_and_invalidation_discards_it(self):
        calls = []
        def producer(reader,params):
            calls.append(1);return {'value':len(calls)}
        self.service.query(producer,{})
        for _ in range(4):
            self.assertEqual(self.service.query(producer,{},ttl=-1)['value'],1)
        self.assertEqual(len(self.service.queue),1)
        self.service.invalidate()
        self.assertFalse(self.service.queue)
        self.assertEqual(self.service.query(producer,{})['value'],2)

    def test_cached_read_reports_live_ingestion_failure_and_retry_clears_it(self):
        calls = []
        def producer(reader, params):
            calls.append(1)
            return {'total': 1, 'events': []}
        self.assertNotIn('error', self.service.query(producer, {}))
        real = self.db.conn
        failing = mock.Mock(wraps=real)
        failing.executemany.side_effect = sqlite3.OperationalError('database is full')
        self.db.add({'ts': self.stamp, 'type': 'dns'}, '{}')
        self.db.conn = failing
        self.db.flush()
        self.assertIn('database is full', self.service.query(producer, {})['error'])
        self.assertEqual(len(calls), 1, 'a cache hit must still report the writer error')
        self.assertFalse(self.db.write_blocked)
        self.db.conn = real
        self.db.flush()
        self.assertNotIn('error', self.service.query(producer, {}))

    def test_corruption_preserves_pending_batch_and_stops_ingestion_and_retention(self):
        real = self.db.conn
        failing = mock.Mock(wraps=real)
        error = sqlite3.DatabaseError('database disk image is malformed')
        error.sqlite_errorcode = sqlite3.SQLITE_CORRUPT
        failing.executemany.side_effect = error
        self.db.add({'ts': self.stamp, 'type': 'dns'}, '{}')
        self.db.conn = failing
        try:
            self.db.flush()
            self.assertTrue(self.db.write_blocked)
            self.assertEqual(len(self.db.buf), 1)
            self.db.flush()
            self.db.maintain(force=True)
            with mock.patch.object(m.os, 'stat', side_effect=AssertionError('ingestion advanced')):
                self.app.store.ingest()
            failing.executemany.assert_called_once()
            self.assertEqual(self.app.store.offset, 0)
            self.db.last_error = ''
            self.assertIn('malformed', self.db.stats()['error'])
        finally:
            self.db.conn = real

    def test_bounded_prefetch_and_no_recursive_page_chain(self):
        for index in range(100):
            self.service.schedule(str(index),lambda:None)
        self.assertEqual(len(self.service.queue),16)
        self.service.queue.clear()
        def producer(reader,params):
            return {'total':1000,'events':[]}
        self.service.query(producer,{'offset':'0','limit':'50'},pages=True)
        self.assertEqual(len(self.service.queue),1)
        _,task = self.service.queue.popitem()
        task[1]()
        self.assertFalse(self.service.queue,'prefetch must not walk all pages')

    def test_read_worker_and_backfill_settings_are_applied(self):
        self.app.config = {'read_workers':3}
        service = m.DataService(self.app,self.cache)
        try:
            self.assertEqual(service.read_workers,3)
            self.assertTrue(all(service.slots.acquire(blocking=False) for _ in range(3)))
            self.assertFalse(service.slots.acquire(blocking=False))
            for _ in range(3):
                service.slots.release()
        finally:
            service.close()
        stats = m.StoredNetworkStats(self.db,batch_size=256,duty_percent=10)
        self.assertEqual((stats.batch_size,stats.duty_percent),(256,10))

    def test_projection_cursor_is_read_inside_the_query_snapshot(self):
        self.add('flow');self.sync(initial=True);self.db.analytics=self.stats
        original=self.service.sql.snapshot
        def changed(*args,**kwargs):
            self.derived.execute("UPDATE meta SET v='0' WHERE k='ready'")
            self.derived.execute('DELETE FROM facts');self.derived.commit()
            return original(*args,**kwargs)
        with mock.patch.object(self.service.sql,'snapshot',side_effect=changed):
            self.assertFalse(self.service.execute(lambda reader:hasattr(reader.db,'summary_cursor')))

    def test_list_dto_never_selects_or_decompresses_raw_and_detail_is_guarded(self):
        self.add(payload='evidence'*10000,community_id='1:test')
        statements = []
        self.db.conn.set_trace_callback(statements.append)
        with mock.patch.object(m.zlib,'decompress',side_effect=AssertionError('eager evidence')):
            count,rows = self.db.search_range(self.stamp-1,self.stamp+1,list_view=True)
        self.db.conn.set_trace_callback(None)
        self.assertEqual(count,1)
        self.assertTrue(set(rows[0]).issubset(m.LIST_FIELDS))
        self.assertNotIn('_raw',rows[0]);self.assertNotIn('flow_id',rows[0])
        self.assertFalse(any('SELECT id,' in sql and ' raw' in sql for sql in statements))
        token = rows[0]['record_id']
        self.assertEqual(self.db.read_record(token)['raw']['payload'],'evidence'*10000)
        self.assertIsNone(self.db.read_record(token+'modified'))
        self.db.clear();self.add(ts=self.stamp+1,payload='replacement')
        self.assertIsNone(self.db.read_record(token),'reused sqlite ID exposed different evidence')

    def test_compact_ingestion_keeps_detail_and_filters(self):
        raw = dict(timestamp=m.iso(self.stamp),event_type='tls',src_ip='192.0.2.1',
                   dest_ip='198.51.100.2',proto='TCP',tls=dict(sni='hidden.example',subject='x'*10000))
        Path(self.app.store.path).write_text(json.dumps(raw)+'\n',encoding='utf-8')
        self.app.store.ingest();self.db.flush()
        cached = self.app.store.events[0]
        self.assertNotIn('subject',cached);self.assertNotIn('_raw',cached)
        count,rows = self.app.store.query(start=self.stamp-1,end=self.stamp+1,
                                         matcher=lambda ev:ev.get('sni')=='hidden.example')
        self.assertEqual(count,1);self.assertEqual(rows[0]['subject'],'x'*10000)

    def test_tuple_normalization_and_incomplete_fields(self):
        hashed = m.tuple_hash('2001:db8::1',123,'2001:db8::2',443,'TCP')
        self.assertEqual(hashed,m.tuple_hash('2001:0db8::2','443','2001:db8::1','123','006'))
        self.assertNotEqual(hashed,m.tuple_hash('2001:db8::1',123,'2001:db8::2',443,'UDP'))
        for args in [('192.0.2.1',None,'198.51.100.2',443,'TCP'),
                     ('bad',1,'198.51.100.2',2,'TCP'),('192.0.2.1',1,'2001:db8::2',2,'TCP')]:
            self.assertIsNone(m.tuple_hash(*args))

    def test_derived_projection_matches_raw_for_arbitrary_boundaries_and_global_top(self):
        rng = random.Random(20261101)
        for index in range(230):
            self.add(kind=('flow','dns','tls','http','alert')[index%5],ts=self.stamp+rng.randrange(600000)/1000,
                     src_ip='192.0.2.'+str(index%19+1),dest_ip='198.51.100.'+str(index%13+1),
                     app_proto='app'+str(index%11),dns={'rrname':'name'+str(index%12)},
                     tls={'sni':'name'+str(index%12)},
                     flow={'bytes_toserver':index,'bytes_toclient':index%7,'pkts_toserver':index%2,'pkts_toclient':index%3})
        # A repeated low-per-bucket value must still compete in the global top list.
        for minute in range(10):
            self.add('flow',self.stamp+minute*60+1,app_proto='global')
            self.add('flow',self.stamp+minute*60+2,app_proto='global')
        self.sync(initial=True,batch=31)
        self.assertNotIn('raw',[row[1] for row in self.derived.execute('PRAGMA table_info(facts)')])
        ranges = [(self.stamp,self.stamp+600),(self.stamp+13.123,self.stamp+499.777),
                  (self.stamp+59.999,self.stamp+60),(self.stamp+60,self.stamp+120),
                  (self.stamp+71.2,self.stamp+71.2),(0,1)]
        for low,high in ranges:
            with self.subTest(low=low,high=high):
                expected = m.EventDB.compute_network_summary(self.source,low,high)
                actual = self.stats.aggregate(self.derived,low,high)
                expected.pop('as_of');actual.pop('as_of')
                self.assertEqual(actual,expected)

    def test_retention_restart_and_clear_with_reused_ids(self):
        for index in range(15):
            self.add('flow',self.stamp+index)
        self.sync(initial=True,batch=4)
        self.db.conn.execute('DELETE FROM events WHERE id<=4');self.db.conn.commit()
        self.db.network_generation += 1
        self.sync()
        self.assertEqual(self.derived.execute('SELECT COUNT(*) FROM facts').fetchone()[0],11)
        self.db.clear()
        self.add('flow',self.stamp+30,app_proto='new')
        self.sync()
        self.assertEqual(self.derived.execute('SELECT COUNT(*) FROM facts').fetchone()[0],1)
        self.assertEqual(self.derived.execute('SELECT app FROM facts').fetchone()[0],'new')
        # Restart with an already caught-up projection does not double-count.
        self.stats.generation = -1
        self.sync(initial=True)
        self.assertEqual(self.derived.execute('SELECT SUM(n) FROM counts').fetchone()[0],1)

    def test_summary_failure_falls_back_and_generation_rejects_old_results(self):
        self.add('flow');self.sync(initial=True)
        self.db.analytics = self.stats
        result = self.stats.summary(self.stamp-1,self.stamp+1,lambda:False)
        self.assertEqual(result['flows'],1)
        self.db.network_generation += 1
        self.assertIsNone(self.stats.summary(self.stamp-1,self.stamp+1,lambda:False))
        self.sync()
        self.derived.execute('DROP TABLE flows');self.derived.commit()
        self.assertIsNone(self.stats.summary(self.stamp-1,self.stamp+1,lambda:False))
        self.assertTrue(self.stats.error)

    def test_indexed_tuple_lookup_includes_unindexed_tail(self):
        self.add('tls');self.add('flow',self.stamp-1,flow_id=99);self.sync(initial=True)
        self.db.analytics = self.stats
        self.add('dns',self.stamp+1)
        hashed = m.tuple_hash('192.0.2.1',12345,'198.51.100.2',443,'TCP')
        result = self.app.hunt({'q':'tuple_hash:'+hashed,'from':str(self.stamp-1),
                                'to':str(self.stamp+2),'view':'list'})
        self.assertEqual(result['total'],2)

    def test_related_flow_context_is_specific_to_each_tuple(self):
        added = {}
        def put(name,**fields):
            stamp = self.stamp+len(added)
            added[name] = stamp
            self.add(ts=stamp,**fields)
        put('primary_a',community_id='1:flows',flow_id=11)
        put('primary_b',community_id='1:flows',flow_id=22,src_port=12346)
        put('matching_a',flow_id=11)
        put('matching_b',flow_id=22,src_port=12346)
        put('wrong_tuple_for_flow',flow_id=22)
        put('another_flow',flow_id=33)
        put('anonymous_a')
        put('anonymous_b',src_port=12346)
        put('zero_flow',flow_id=0)
        put('another_community',community_id='1:other',flow_id=11)
        def result_for(params):
            related = self.app.hunt_related(params)
            result = self.app.hunt({'q':related['query'],'from':str(related['from']),
                                    'to':str(related['to']),'icase':'1','view':'list'})
            return related,{row['ts'] for row in result['events']}
        related,actual = result_for({'community':'1:flows'})
        expected = {added[name] for name in ('primary_a','primary_b','matching_a','matching_b','anonymous_a','anonymous_b','zero_flow')}
        self.assertEqual(actual,expected)
        self.assertIn('flow: 11',related['query']);self.assertIn('flow: 22',related['query'])
        self.assertNotIn('tuple_hash',related['query'])
        self.assertEqual(related['flow_count'],2)
        params = dict(src='192.0.2.1',sport=12345,dst='198.51.100.2',dport=443,proto='TCP')
        _,actual = result_for(dict(params,flow='11'))
        self.assertEqual(actual,{added[name] for name in ('matching_a','anonymous_a','zero_flow')})
        _,actual = result_for(params)
        self.assertEqual(actual,{added[name] for name in ('anonymous_a','zero_flow')})

    def test_large_flow_identity_is_lossless_and_not_a_tuple_hash_fallback(self):
        flow = 9007199254740993
        self.add(flow_id=flow)
        self.add(ts=self.stamp+1,flow_id=flow-1)
        _,groups = self.db.security_incidents(self.stamp-1,self.stamp+3)
        self.assertEqual(len(groups),2)
        self.assertTrue(all(row['id'].startswith('event:') and not row['association_flow_id'] for row in groups))
        _,rows = self.db.search_range(self.stamp-1,self.stamp+3,list_view=True)
        for row in rows:
            detail = self.db.read_record(row['record_id'])['record']
            self.assertIn(detail['association_flow_id'],{str(flow),str(flow-1)})
            self.assertIsNone(detail['tuple_hash'])

    def test_related_flow_limit_is_explicit_and_maximum_is_searchable(self):
        for index in range(self.db.MAX_RELATED_FLOWS):
            self.add(ts=self.stamp+index,community_id='1:flow-limit',flow_id=index+1)
        related = self.app.hunt_related({'community':'1:flow-limit'})
        self.assertEqual(related['flow_count'],self.db.MAX_RELATED_FLOWS)
        self.add(ts=self.stamp+self.db.MAX_RELATED_FLOWS,community_id='1:flow-limit',flow_id=self.db.MAX_RELATED_FLOWS+1)
        with self.assertRaisesRegex(ValueError,'Flow ID 过多'):
            self.app.hunt_related({'community':'1:flow-limit'})

    def test_tuple_query_sql_and_memory_agree_for_boolean_patterns(self):
        records = []
        for index,extra in enumerate(({},{'community_id':'1:priority'},{'src_port':None})):
            raw = self.add(ts=self.stamp+index,**extra)
            records.append(m.EventStore._parse(json.dumps(raw))[0])
        hashed = m.tuple_hash('192.0.2.1',12345,'198.51.100.2',443,'TCP')
        for term in (hashed,hashed.upper(),hashed[:5]+'*','*','missing'):
            for query in ('tuple_hash:'+term,'NOT tuple_hash:'+term,'tuple_hash:'+term+' OR community_id:1:priority'):
                expected = sum(m.hunt_match(m.hunt_parse(query),record) for record in records)
                result = self.app.hunt({'q':query,'from':str(self.stamp-1),'to':str(self.stamp+3),'view':'list'})
                self.assertEqual(result['total'],expected,query)

    def test_community_pivot_uses_index_across_a_wide_range(self):
        community = '1:AbCdEfGh0123456789+/='
        self.add(ts=self.stamp,community_id=community)
        self.add('dns',self.stamp+172800,community_id=community)
        self.add('dns',self.stamp+1,community_id=community.lower())
        self.db.conn.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20000) INSERT INTO events(ts,type,community) SELECT ?+x,'dns','1:unrelated' FROM n",(self.stamp*1000,))
        self.db.conn.commit()
        bounds = self.db.community_range(community)
        self.app._data_reader = True
        for alias in ('community','community_id'):
            for icase in ('','1'):
                calls = [0]
                def budget():
                    calls[0] += 1
                    return calls[0]>100
                self.db.conn.set_progress_handler(budget,1000)
                try:
                    data = self.app.hunt(dict(q=alias+': '+json.dumps(community),view='list',icase=icase,
                                              **{key:str(value) for key,value in bounds.items()}))
                finally:
                    self.db.conn.set_progress_handler(None,0)
                self.assertEqual(data['total'],2,(alias,icase))
                self.assertTrue(m.hunt_match(m.hunt_parse(alias+': '+json.dumps(community)),{'community':community},bool(icase)))
                self.assertFalse(m.hunt_match(m.hunt_parse(alias+': '+json.dumps(community)),{'community':community.lower()},bool(icase)))

    def test_interrupted_query_raises_instead_of_reporting_empty_success(self):
        self.add()
        self.app._data_reader = True
        self.db.conn.set_progress_handler(lambda:1,1)
        try:
            with self.assertRaisesRegex(RuntimeError,'中断|超时'):
                self.app.hunt({'from':str(self.stamp-1),'to':str(self.stamp+1),'view':'list'})
        finally:
            self.db.conn.set_progress_handler(None,0)

    def test_related_query_covers_all_tuples_and_excludes_other_communities(self):
        community = '1:multi-tuple'
        self.add(ts=self.stamp,community_id=community)
        self.add(ts=self.stamp+1,community_id=community,src_port=12346)
        self.add(ts=self.stamp+6,community_id=community,src_port=None)
        self.add('dns',self.stamp+2)
        self.add('tls',self.stamp+3,src_ip='198.51.100.2',src_port=443,dest_ip='192.0.2.1',dest_port=12346)
        self.add('dns',self.stamp-3600)
        self.add('dns',self.stamp+3600,src_port=12346)
        self.add('dns',self.stamp+4,community_id='1:another')
        self.add('dns',self.stamp+5,src_port=50000)
        columns = self.db.conn.execute('PRAGMA table_info(events)').fetchall()
        related = self.app.hunt_related({'community':community})
        self.assertEqual(related['tuple_count'],2)
        self.assertNotIn('tuple_hash',related['query'])
        self.assertIn('NOT community_id:*',related['query'])
        result = self.app.hunt({'q':related['query'],'from':str(related['from']),
                                'to':str(related['to']),'icase':'1','view':'list'})
        expected = {self.stamp,self.stamp+1,self.stamp+6,self.stamp+2,self.stamp+3,self.stamp-3600,self.stamp+3600}
        self.assertEqual({row['ts'] for row in result['events']},expected)
        self.assertEqual(result['total'],len(expected))
        self.assertEqual(self.db.conn.execute('PRAGMA table_info(events)').fetchall(),columns)

    def test_related_ipv6_and_fallback_queries_cover_both_directions(self):
        first = dict(src_ip='2001:db8::1',src_port=12345,dest_ip='2001:db8::2',dest_port=443)
        reverse = dict(src_ip='2001:db8::2',src_port=443,dest_ip='2001:db8::1',dest_port=12345)
        self.add(ts=self.stamp,community_id='1:ipv6',**first)
        self.add('dns',self.stamp+1,**first)
        self.add('tls',self.stamp+2,**reverse)
        self.add('dns',self.stamp+3,community_id='1:other',**reverse)
        for params,expected in [({'community':'1:ipv6'},3),
                                ({'src':first['src_ip'],'sport':12345,'dst':first['dest_ip'],'dport':443,'proto':'TCP'},2)]:
            related = self.app.hunt_related(params)
            self.assertNotIn('tuple_hash',related['query'])
            result = self.app.hunt({'q':related['query'],'from':str(related['from']),
                                    'to':str(related['to']),'icase':'1','view':'list'})
            self.assertEqual(result['total'],expected)

    def test_related_query_deduplicates_reverse_tuple_and_rejects_overflow(self):
        self.add(community_id='1:reverse')
        self.add(ts=self.stamp+1,community_id='1:reverse',src_ip='198.51.100.2',src_port=443,dest_ip='192.0.2.1',dest_port=12345)
        self.assertEqual(self.app.hunt_related({'community':'1:reverse'})['tuple_count'],1)
        for index in range(self.db.MAX_RELATED_TUPLES+1):
            self.add(ts=self.stamp+index,community_id='1:many',src_port=20000+index)
        with self.assertRaisesRegex(ValueError,'过多'):
            self.app.hunt_related({'community':'1:many'})

    def test_related_union_keeps_index_access_and_boolean_expansion_is_bounded(self):
        self.add(community_id='1:indexed')
        self.add('dns',self.stamp+1)
        for field in ('src','dst','dport'):
            self.db.conn.execute('CREATE INDEX local_'+field+' ON events('+field+',ts)')
        self.db.conn.commit()
        related = self.app.hunt_related({'community':'1:indexed'})
        clauses,args,complete = m.hunt_sql_pushdown(m.hunt_parse(related['query']),True)
        self.db._hunt_functions()
        plan = [row[3] for row in self.db.conn.execute('EXPLAIN QUERY PLAN SELECT COUNT(*) FROM events WHERE '+' AND '.join(clauses),args)]
        self.assertTrue(complete);self.assertIn('MULTI-INDEX OR',plan)
        self.assertNotIn('SCAN events',plan)
        query = ' AND '.join('(sport:1 OR sport:2)' for _ in range(10))
        _,args,complete = m.hunt_sql_pushdown(m.hunt_parse(query))
        self.assertTrue(complete)
        self.assertLessEqual(len(args),20,'large Boolean products must retain the compact predicate')


class HTTPConcurrencyCase(unittest.TestCase):
    def test_slow_request_body_does_not_hold_the_mutation_lock(self):
        reading=threading.Event()
        class Handler(m.Handler):
            def log_message(self,*_):pass
            def _require(self,*_,**__):return True
            def _read_body(self,limit):
                if self.path=='/api/slow':reading.set()
                return super()._read_body(limit)
            def _mutate(self,*_):return self._json({'ok':True})
        with m.BoundedHTTPServer(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            slow=http.client.HTTPConnection(*server.server_address,timeout=3)
            normal=http.client.HTTPConnection(*server.server_address,timeout=3)
            try:
                slow.putrequest('POST','/api/slow');slow.putheader('Content-Length','2');slow.putheader('X-Requested-With','ips-web');slow.endheaders();slow.send(b'{')
                self.assertTrue(reading.wait(2))
                normal.request('POST','/api/normal',body='{}',headers={'X-Requested-With':'ips-web'})
                response=normal.getresponse();self.assertEqual(response.status,200);response.read()
                slow.send(b'}');response=slow.getresponse();self.assertEqual(response.status,200);response.read()
            finally:normal.close();slow.close();server.shutdown();thread.join(3)

    def test_connection_limit_returns_overload_and_releases_finished_slots(self):
        entered=threading.Condition();release=threading.Event();active=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                with entered:active.append(self.path);entered.notify_all()
                if self.path=='/slow':release.wait(3)
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
        class Server(m.BoundedHTTPServer):MAX_CONNECTIONS=2
        with Server(('127.0.0.1',0),Handler) as server,concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def request(path):
                connection=http.client.HTTPConnection(*server.server_address,timeout=3)
                try:
                    connection.request('GET',path);response=connection.getresponse();response.read();return response.status
                finally:connection.close()
            try:
                futures=[pool.submit(request,'/slow') for _ in range(2)]
                with entered:self.assertTrue(entered.wait_for(lambda:len(active)==2,2))
                self.assertEqual(request('/overflow'),503);self.assertEqual(len(active),2)
                release.set();self.assertEqual([f.result(3) for f in futures],[200,200])
                self.assertEqual(request('/after'),200)
            finally:release.set();server.shutdown();thread.join(3)

    def test_stream_limit_preserves_ordinary_http_and_shutdown_wakes_stream(self):
        ended=threading.Event()
        class Handler(m.Handler):
            def log_message(self,*_):pass
            def _session(self):return {'user':'fixture'}
            def _stream_payload(self,*_):return {'ready':True}
            def do_GET(self):
                if self.path=='/stream':
                    try:self._stream({})
                    finally:ended.set()
                else:self._json({'ready':True})
        class Server(m.BoundedHTTPServer):MAX_STREAMS=1
        with Server(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            first=http.client.HTTPConnection(*server.server_address,timeout=3)
            try:
                first.request('GET','/stream');response=first.getresponse();self.assertEqual(response.status,200)
                self.assertTrue(response.fp.readline().startswith(b'data:'))
                for path,status in (('/stream',503),('/ordinary',200)):
                    connection=http.client.HTTPConnection(*server.server_address,timeout=3)
                    try:
                        connection.request('GET',path);reply=connection.getresponse();reply.read();self.assertEqual(reply.status,status)
                    finally:connection.close()
                server.shutdown();thread.join(3)
                server.server_close();self.assertTrue(ended.wait(2),'SSE sleep did not wake on shutdown')
            finally:first.close();server.shutdown();thread.join(3)


if __name__ == '__main__':
    unittest.main()
