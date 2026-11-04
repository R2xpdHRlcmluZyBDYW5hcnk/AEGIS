"""A blocked native reload or rule RPC must not consume the Web read budget."""
from concurrent.futures import ThreadPoolExecutor
import copy
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
import types
import unittest
from unittest import mock

from tests import test_rule_manager as fixture
from runtime_status import RuntimeReader,ENGINE_READS
import ips_control


class RuntimeStatusCase(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.ManagerCase();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.manager=self.fixture.manager;self.snapshot=self.manager.runtime
        self.path=self.fixture.base/'status.json'
        self.snapshot.engine={key:None for key in ENGINE_READS}
        self.snapshot.engine.update({'version':'fixture','running-mode':'inline','capture-mode':'NFQ',
            'ruleset-stats':dict(rules_loaded=1,rules_failed=None,rules_skipped=None),
            'dump-counters':dict(ips=dict(accepted=7,blocked=2),decoder=dict(pkts=9,bytes=128))})
        self.snapshot.as_of=time.time();self.snapshot.error=''
        self.snapshot.service=dict(state='active',pid=123,uptime=30,memory=4096,cpu_seconds=0)
        self.snapshot.publish(self.path)

    def test_system_overview_and_history_respond_during_reload_and_catalog_lock(self):
        web=fixture.engine();web.EVE=str(self.fixture.base/'events.json');Path(web.EVE).write_text('')
        reader=RuntimeReader(self.path);client=mock.Mock()
        client.request.side_effect=AssertionError('Web query contacted blocked rule RPC')
        ips_control.install_proxies(web,client,reader)
        app=object.__new__(web.App)
        app.config=dict(web.DEFAULT_CONFIG,read_workers=2);app.started=web.now()
        app.db=web.EventDB(str(self.fixture.base/'events.db'));self.addCleanup(app.db.conn.close)
        app.cache=web.SharedCache(1<<20);app.store=web.EventStore(web.EVE);app.store.db=app.db
        app.sys=web.SysInfo();app.network=types.SimpleNamespace(get=lambda *a,**kw:{})
        app.sessions=web.Sessions(3600);token=app.sessions.create('fixture','127.0.0.1')
        app.data=web.DataService(app,app.cache);self.addCleanup(app.data.close)
        raw=dict(timestamp=web.iso(web.now()),event_type='alert',src_ip='192.0.2.1',dest_ip='198.51.100.1',
                 alert=dict(signature='fixture',signature_id=1,severity=1,action='allowed'))
        app.db.add(*web.EventStore._parse(json.dumps(raw)));app.db.flush()
        class Handler(web.Handler):
            def log_message(self,*args):pass
        Handler.app=app;Handler.config=app.config
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
        serving=threading.Thread(target=server.serve_forever,daemon=True);serving.start()
        entered,release,stop=threading.Event(),threading.Event(),threading.Event()
        def blocked_reload(commands,timeout=300):
            self.assertEqual(commands,['ruleset-reload-rules']);entered.set()
            if not release.wait(10):raise RuntimeError('synthetic reload deadline')
            return {'ruleset-reload-rules':{'confirmed':True}}
        def request(path):
            connection=http.client.HTTPConnection(*server.server_address,timeout=2)
            try:
                connection.request('GET',path,headers={'Cookie':'ipsweb_session='+token})
                response=connection.getresponse();value=json.loads(response.read())
                self.assertEqual(response.status,200,value);return value
            finally:connection.close()
        try:
            with mock.patch.object(self.manager.jobs,'run'),mock.patch.object(self.manager.jobs.local.engine,'call',side_effect=blocked_reload):
                self.assertTrue(self.fixture.mutate('/api/actions/apply')['ok'])
                self.assertTrue(entered.wait(2))
                self.snapshot.publish(self.path)
                # Catalog readers can own this lock while an engine call waits.
                # Neither the telemetry file nor event SQLite reads need it.
                with self.manager.lock,ThreadPoolExecutor(max_workers=4) as pool:
                    pending={path:pool.submit(request,path) for path in ('/api/system','/api/overview','/api/hunt?limit=1','/api/actions/status')}
                    results={path:future.result(3) for path,future in pending.items()}
                    status=pool.submit(self.manager.dispatch,dict(operation='read',name='sys.update_status',args=[],kwargs={}))
                    self.assertEqual(status.result(1)['state'],'running')
                self.assertEqual(results['/api/overview']['security']['total'],1)
                self.assertEqual(results['/api/hunt?limit=1']['total'],1)
                self.assertEqual(results['/api/system']['counters']['ips']['accepted'],7)
                self.assertTrue(results['/api/system']['telemetry']['updating'])
                self.assertTrue(results['/api/system']['telemetry']['stale'])
                self.assertEqual(results['/api/actions/status']['state'],'running')
                self.assertFalse(release.is_set())
                with app.store.lock,ThreadPoolExecutor(max_workers=1) as pool:
                    self.assertEqual(pool.submit(request,'/api/hunt?limit=2&view=list').result(2)['total'],1)
                app.data.slots.acquire();app.data.slots.acquire()
                try:
                    self.assertEqual(request('/api/system')['service']['pid'],123)
                finally:
                    app.data.slots.release();app.data.slots.release()
                client.request.assert_not_called()
                release.set();self.assertEqual(self.fixture.wait()['rc'],0)
        finally:
            release.set();stop.set();server.shutdown();server.server_close();serving.join(timeout=5)

    def test_reader_retains_last_good_values_but_marks_missing_or_invalid_publication_stale(self):
        reader=RuntimeReader(self.path)
        self.assertEqual(reader.engine_call(['dump-counters'])['dump-counters']['ips']['accepted'],7)
        self.path.write_text('{incomplete')
        value=reader.read();self.assertTrue(value['telemetry']['stale']);self.assertTrue(value['telemetry']['error'])
        self.assertEqual(value['engine']['dump-counters']['ips']['accepted'],7)
        self.path.unlink();self.assertTrue(reader.read()['telemetry']['stale'])
        empty=RuntimeReader(self.path).engine_call(['ruleset-stats'])
        self.assertNotIn('ruleset-stats',empty);self.assertIn('__error__',empty)

    def test_failed_sample_keeps_previous_timestamp_and_recovers_after_job(self):
        prior=self.snapshot.as_of;engine=copy.deepcopy(self.snapshot.engine)
        with mock.patch.object(self.manager.jobs.local,'service',return_value={'pid':124}), \
                mock.patch.object(self.manager.module,'nft_query_table',return_value={}), \
                mock.patch.object(self.manager.jobs.local.engine,'call',return_value={'__error__':'native unavailable'}) as native:
            self.snapshot.sample();self.assertEqual(self.snapshot.as_of,prior);self.assertEqual(self.snapshot.engine,engine)
            self.manager.busy=True;self.snapshot.sample();self.assertEqual(native.call_count,1)
            self.assertEqual(self.snapshot.payload()['service']['pid'],124)
            self.manager.busy=False;native.return_value=engine;self.snapshot.sample()
        self.assertGreaterEqual(self.snapshot.as_of,prior);self.assertEqual(self.snapshot.error,'')

    def test_publication_continues_while_native_sampler_waits(self):
        entered,release,stop=threading.Event(),threading.Event(),threading.Event()
        previous=self.snapshot.as_of
        def native(*args,**kwargs):
            entered.set()
            if not release.wait(5):raise RuntimeError('synthetic sample timeout')
            return self.snapshot.engine
        with mock.patch.object(self.manager.jobs.local,'service',return_value={'pid':124}), \
                mock.patch.object(self.manager.module,'nft_query_table',return_value={}), \
                mock.patch.object(self.manager.jobs.local.engine,'call',side_effect=native):
            threads=self.snapshot.start(stop,self.path)
            try:
                self.assertTrue(entered.wait(2));self.manager.busy=True
                reader=RuntimeReader(self.path);deadline=time.monotonic()+2
                with self.manager.lock:
                    while time.monotonic()<deadline and not reader.read()['telemetry'].get('updating'):
                        stop.wait(.02)
                    self.assertTrue(reader.read()['telemetry']['updating'])
                    self.assertEqual(reader.read()['service']['pid'],124)
                self.assertFalse(release.is_set())
            finally:
                stop.set();release.set()
                for thread in threads:thread.join(timeout=3)
        self.assertEqual(self.snapshot.as_of,previous)

    def test_apply_acknowledgement_already_has_published_running_status(self):
        self.snapshot.path=self.path
        release=threading.Event()
        def reload(*args,**kwargs):
            if not release.wait(5):raise RuntimeError('synthetic reload timeout')
            return {'ruleset-reload-rules':{'confirmed':True}}
        try:
            with mock.patch.object(self.manager.jobs,'run'),mock.patch.object(self.manager.jobs.local.engine,'call',side_effect=reload):
                self.assertTrue(self.fixture.mutate('/api/actions/apply')['ok'])
                reader=RuntimeReader(self.path)
                self.assertEqual(reader.read()['update_status']['state'],'running')
                self.assertTrue(reader.read()['telemetry']['updating'])
                release.set();self.assertEqual(self.fixture.wait()['rc'],0)
                deadline=time.monotonic()+2
                while reader.read()['update_status']['state']!='done' and time.monotonic()<deadline:time.sleep(.01)
                self.assertEqual(reader.read()['update_status']['state'],'done')
        finally:release.set()


if __name__=='__main__':unittest.main()
