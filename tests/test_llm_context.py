"""Exact session retrieval, safe model-authored hunting and evidence-fed summaries."""
import http.client
from http.server import ThreadingHTTPServer
import json
import threading
import time
import unittest
from unittest import mock

from tests import test_data_layer as fixture
from tests.test_llm_assistant import Provider
from llm_assistant import LocalAssistant, summary_payload, SUMMARY_PROMPT, hunt_options, hunt_plan_payload, select_hunts

m = fixture.m
FIRST = 'a'*32+':0000000000000001'
SECOND = 'a'*32+':0000000000000002'
RESTART = 'b'*32+':0000000000000001'


class SessionContextTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.DataLayerCase();self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.app,self.db,self.stamp = self.fixture.app,self.fixture.db,self.fixture.stamp

    def add(self,kind='tls',offset=0,session=FIRST,**extra):
        if session:extra['snort_native']=dict(session_id=session)
        if kind not in ('alert','drop'):extra.setdefault('alert',{})
        return self.fixture.add(kind,self.stamp+offset,**extra)

    def target(self,kind='tls'):
        _,rows=self.db.search_range(self.stamp-1,self.stamp+10000,types=[kind],
            push=(['session_id=?'],[FIRST]),list_view=True,limit=1)
        return dict(kind='record',key=rows[0]['record_id'])

    def test_normal_session_retrieves_protocol_and_flow_facts_across_time_without_raw(self):
        self.add('flow',0,app_proto='tls',flow=dict(state='closed',reason='timeout',bytes_toserver=1234,bytes_toclient=5678,pkts_toserver=3,pkts_toclient=4))
        self.add('tls',3600,app_proto='tls',tls=dict(sni='normal.example.test',version='TLS 1.3'))
        self.add('http',7200,app_proto='http',http=dict(hostname='normal.example.test',http_method='GET',status=200,url='/status?token=private-fixture'))
        self.add('alert',2,SECOND,alert=dict(signature='Different session attack',signature_id=42,severity=1))
        self.add('alert',3,RESTART,alert=dict(signature='Different epoch attack',signature_id=43,severity=1))
        self.add('alert',4,None,alert=dict(signature='Anonymous attack',signature_id=44,severity=1))
        with mock.patch.object(m.zlib,'decompress',side_effect=AssertionError('raw blobs must not be read')):
            context=self.app.summary_context(self.target())
        self.assertEqual(context['total_records'],3)
        self.assertEqual(context['event_counts'],{'flow':1,'tls':1,'http':1})
        self.assertEqual(context['action_counts'],{})
        self.assertEqual(context['last_ts'],self.stamp+7200)
        payload,meta=summary_payload(context)
        data=json.loads(payload['messages'][1]['content'])
        self.assertEqual(data['flow']['bytes_toserver'],1234)
        self.assertEqual(data['flow']['bytes_toclient'],5678)
        self.assertIn('normal.example.test',payload['messages'][1]['content'])
        self.assertNotIn('Different session',payload['messages'][1]['content'])
        self.assertNotIn('private-fixture',payload['messages'][1]['content'])
        self.assertEqual(meta['scope'],'session')
        self.assertIn('无攻击依据就分析通信',SUMMARY_PROMPT)
        self.assertLessEqual(sum(len(v['content'].encode()) for v in payload['messages']),1500)

    def test_no_session_never_merges_by_shared_endpoints_community_or_flow(self):
        for offset in range(3):self.add('tls',offset,None,community_id='shared',flow_id=123)
        _,rows=self.db.search_range(self.stamp-1,self.stamp+10,list_view=True)
        context=self.app.summary_context(dict(kind='record',key=rows[0]['record_id']))
        self.assertEqual(context['scope'],'event');self.assertEqual(context['total_records'],1)

    def test_hunt_queries_execute_same_dsl_but_cannot_escape_session_or_read_payloads(self):
        for offset in range(8):self.add('http',offset,app_proto='http',http=dict(status=403))
        self.add('http',9,SECOND,app_proto='http',http=dict(status=500))
        with mock.patch.object(m.zlib,'decompress',side_effect=AssertionError('raw')):
            result=self.app.summary_hunt(dict(session_id=FIRST,query='type:http AND status:>=400'))
        self.assertEqual(result['total'],8);self.assertEqual(len(result['records']),4)
        self.assertTrue(all(r['session_id']==FIRST for r in result['records']))
        self.assertIn('session_id: '+json.dumps(FIRST),result['query'])
        self.assertIsNotNone(m.hunt_parse(result['query']))
        for query in ('session_id:"'+SECOND+'"','payload:secret','type:http OR session_id:*','free text',
                      'status:not-a-number','type:http '*40,'type:http OR "x OR 1=1"'):
            with self.subTest(query=query),self.assertRaises(ValueError):
                self.app.summary_hunt(dict(session_id=FIRST,query=query))

    def test_signed_incident_summary_uses_same_full_session_as_record_summary(self):
        self.add('alert',0,alert=dict(signature='Observed command',signature_id=15,severity=2,action='allowed'))
        self.add('drop',200,alert=dict(signature='Observed command',signature_id=15,severity=2,action='blocked'))
        self.add('tls',400,tls=dict(sni='observed.example.test'))
        context=self.app.summary_context(dict(kind='incident',params={'id':'session:'+FIRST,'window':1}))
        self.assertEqual(context['total_records'],3)
        self.assertEqual(context['action_counts']['blocked'],1)
        payload,_=summary_payload(context)
        data=json.loads(payload['messages'][1]['content'])
        self.assertEqual(data['actions']['blocked'],1)
        self.assertIn('Observed command',payload['messages'][1]['content'])


class SummaryPipelineTests(unittest.TestCase):
    setUp=SessionContextTests.setUp
    add=SessionContextTests.add
    target=SessionContextTests.target
    def provider(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Provider);server.daemon_threads=True
        server.entered,server.cancelled,server.stop=threading.Event(),threading.Event(),threading.Event()
        server.stall,server.finish,server.text=False,'stop',None
        threading.Thread(target=server.serve_forever,daemon=True).start()
        def cleanup():server.stop.set();server.shutdown();server.server_close()
        self.addCleanup(cleanup)
        assistant=LocalAssistant()
        assistant.connection=lambda:http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
        return assistant,server

    def test_generated_hunt_hits_and_important_facts_reach_final_model_input(self):
        self.add('flow',0,flow=dict(state='closed',bytes_toserver=1200,bytes_toclient=50))
        self.add('http',1,app_proto='http',http=dict(hostname='observed.example.test',status=403))
        self.add('http',3,app_proto='http',http=dict(hostname='observed.example.test',status=200))
        self.add('tls',2,tls=dict(sni='observed.example.test',version='TLS 1.3'))
        assistant,server=self.provider()
        def respond(payload):
            return json.dumps({'checks':['http_errors']}) if '狩猎助手' in payload['messages'][0]['content'] else '通信概览：HTTP 返回403。研判依据：尚未证实攻击。'
        server.response_for=respond
        output=[]
        assistant.generate(self.app,'owner',dict(kind='summary',target=self.target()),lambda v:output.append(v) or True,lambda:False)
        result=output[-1]['result']
        self.assertEqual(server.calls,2)
        self.assertEqual([h['total'] for h in result['hunts']],[0,1])
        final=json.loads(server.payloads[-1]['messages'][1]['content'])
        self.assertEqual([h['hits'] for h in final['hunt']],[0,1])
        self.assertEqual(final['flow']['bytes_toserver'],1200)
        self.assertTrue(any(r.get('status')==403 for r in final['records']))
        self.assertEqual(result['context']['total_records'],4)

    def test_cancellation_in_second_model_turn_stops_upstream_without_result(self):
        self.add('tls',0)
        assistant,server=self.provider();server.stall_calls={2}
        disconnected=threading.Event();output=[];errors=[]
        def run():
            try:assistant.generate(self.app,'owner',dict(kind='summary',target=self.target()),lambda v:output.append(v) or True,disconnected.is_set)
            except Exception as exc:errors.append(exc)
        thread=threading.Thread(target=run);thread.start()
        deadline=time.monotonic()+3
        while getattr(server,'calls',0)<2 and not errors and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(errors)
        self.assertEqual(server.calls,2)
        disconnected.set();thread.join(1)
        self.assertFalse(thread.is_alive());self.assertTrue(server.cancelled.wait(1))
        self.assertFalse(errors);self.assertFalse(any('result' in v for v in output))

    def test_natural_language_and_malformed_plans_execute_only_valid_fallback_checks(self):
        self.add('tls',0,tls=dict(sni='alpha.example.test'))
        self.add('alert',1,alert=dict(signature='Observed',signature_id=15,severity=2))
        assistant,server=self.provider()
        natural='检查 type:alert 或 action:blocked，同时验证 sni 是否包含 alpha 或 beta。'
        for bad in (natural,json.dumps({'queries':[natural]}),json.dumps({'checks':[natural]}),'```json\n{"checks":[',json.dumps({'checks':['unknown']})):
            with self.subTest(response=bad):
                server.response_for=lambda payload:bad if '狩猎助手' in payload['messages'][0]['content'] else '通信概览：已取得检索结果。'
                output=[]
                assistant.generate(self.app,'owner',dict(kind='summary',target=self.target()),lambda v:output.append(v) or True,lambda:False)
                result=output[-1]['result']
                self.assertEqual(result['hunt_status'],'fallback')
                self.assertEqual(result['hunts'][0]['total'],1)
                self.assertFalse(any(h.get('error') for h in result['hunts']))
                for hunt in result['hunts']:
                    self.assertIsNotNone(m.hunt_parse(hunt['query']))
                    self.assertNotIn('检查',hunt['query'])

    def test_partial_model_plan_falls_back_without_failing_final_summary(self):
        self.add('tls',0,tls=dict(sni='alpha.example.test'))
        assistant,server=self.provider()
        server.response_for=lambda payload:'{"checks":[' if '狩猎助手' in payload['messages'][0]['content'] else '通信概览：普通通信，暂无攻击依据。'
        server.finish_for=lambda payload:'length' if '狩猎助手' in payload['messages'][0]['content'] else 'stop'
        output=[]
        assistant.generate(self.app,'owner',dict(kind='summary',target=self.target()),lambda v:output.append(v) or True,lambda:False)
        self.assertEqual(output[-1]['result']['hunt_status'],'fallback')

    def test_validation_and_execution_errors_have_distinct_reasons(self):
        self.add('tls',0)
        assistant,server=self.provider()
        for error,kind in ((ValueError('invalid'),'validation'),(RuntimeError('interrupted'),'execution')):
            output=[]
            with mock.patch.object(self.app,'summary_hunt',side_effect=error):
                assistant.generate(self.app,'owner',dict(kind='summary',target=self.target()),lambda v:output.append(v) or True,lambda:False)
            self.assertEqual(output[-1]['result']['hunts'][0]['error_kind'],kind)

    def test_all_prepared_checks_compile_and_fit_planner_budget(self):
        self.add('tls',0,tls=dict(sni='alpha.example.test'))
        self.add('http',1,app_proto='http',http=dict(status=403,hostname='beta.example.test'))
        self.add('dns',2,dns=dict(rrname='gamma.example.test',rcode='NXDOMAIN'))
        self.add('flow',3)
        context=self.app.summary_context(self.target())
        options=hunt_options(context)
        for option in options:
            self.assertLessEqual(len(option['query']),160)
            self.assertFalse(self.app.summary_hunt(dict(session_id=FIRST,query=option['query'])).get('error'))
        payload=hunt_plan_payload(context,options)
        self.assertLessEqual(sum(len(p['content'].encode()) for p in payload['messages']),1500)
        example=json.loads(payload['messages'][1]['content'])['reply_example']
        self.assertTrue(set(example['checks'])<={option['id'] for option in options})
        planned,source=select_hunts('{"checks":["names"]}',options)
        self.assertEqual(source,'model');self.assertEqual(planned[-1]['id'],'names')


if __name__=='__main__':unittest.main()
