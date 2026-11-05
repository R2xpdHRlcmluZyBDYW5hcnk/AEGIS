"""Local fake-provider integration: grounding, cancellation and bounded inference."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import select
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_assistant import LocalAssistant, VisibleText, candidates, rule_from_choice, validate_rule, prompt_payload

ROW = dict(src='192.0.2.1', dst='198.51.100.2', dport=80, proto='TCP', app='http', host='example.test', sig='Observed alert')


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.calls = getattr(self.server, 'calls', 0) + 1
        if not hasattr(self.server,'payloads'):self.server.payloads=[]
        self.server.payloads.append(self.server.payload)
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.end_headers()
        self.server.entered.set()
        system=self.server.payload['messages'][0]['content']
        stage='hunt' if '狩猎助手' in system else 'summary' if '四段' in system else 'rule'
        stalled = lambda:(self.server.stall and getattr(self.server,'stall_stage',stage)==stage) or self.server.calls in getattr(self.server,'stall_calls',set())
        if stalled():
            while stalled() and not self.server.stop.is_set():
                if select.select([self.connection], [], [], .05)[0] and not self.connection.recv(1):
                    self.server.cancelled.set()
                    self.server.cancellations = getattr(self.server, 'cancellations', 0) + 1
                    return
            if self.server.stop.is_set():
                return
        text = self.server.response_for(self.server.payload) if hasattr(self.server,'response_for') else self.server.text
        if stage=='hunt' and getattr(self.server,'natural_plan',False):
            text=json.dumps({'queries':['检查 type:alert 或 action:blocked，同时验证 sni 是否包含 alpha 或 beta。']})
        if text is None:
            system=self.server.payload['messages'][0]['content']
            if '狩猎助手' in system:
                text=json.dumps({'queries':[{'query':'proto:TCP AND dport:443','reason':'比较附近的加密连接'}]})
            elif '四段' in system:
                text='通信概览：当前会话存在通信记录。\n行为与处置：结合检索结果核查。\n研判依据：尚不能确认入侵成功。\n建议核查：查看命中日志。'
            else:
                text=json.dumps(dict(candidate=0,message='Observed communication',reason='当前事件的通信端点',limitations='可能匹配正常访问'))
        finish=self.server.finish_for(self.server.payload) if hasattr(self.server,'finish_for') else self.server.finish
        deltas=self.server.deltas_for(self.server.payload) if hasattr(self.server,'deltas_for') else [{'content':text}]
        if stage=='summary' and (getattr(self.server,'stream_prefix',False) or getattr(self.server,'analysis_prefix',False)):
            deltas=[{'reasoning_content':'先观察连接方向'}, {'reasoning_content':'并核对 <i>参考连接</i>。'}, {'content':'分析说'},
                    {'content':'明：先比对目标端口'}, {'content':'与附近会话。\n'+text[:16]}, {'content':text[16:]}]
        for index,delta in enumerate(deltas):
            chunk={'choices':[{'delta':delta,'finish_reason':finish if index==len(deltas)-1 else None}]}
            self.wfile.write(b'data: ' + (json.dumps(chunk).encode() if isinstance(chunk, dict) else chunk.encode()) + b'\n\n')
            self.wfile.flush()
            if stage=='summary' and index in (0,3,4):
                flag={0:'reasoning_prefix',3:'analysis_prefix',4:'stream_prefix'}[index]
                while getattr(self.server,flag,False) and not self.server.stop.is_set():
                    if select.select([self.connection],[],[],.05)[0] and not self.connection.recv(1):
                        self.server.cancelled.set();self.server.cancellations=getattr(self.server,'cancellations',0)+1;return
        self.wfile.write(b'data: [DONE]\n\n');self.wfile.flush()


class AssistantTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        self.server.daemon_threads = True
        self.server.entered, self.server.cancelled, self.server.stop = threading.Event(), threading.Event(), threading.Event()
        self.server.stall, self.server.finish = False, 'stop'
        self.server.text = json.dumps(dict(candidate=0, message='Observed HTTP host', reason='来自当前事件', limitations='可能匹配正常访问'))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.close)
        self.assistant = LocalAssistant()
        self.assistant.connection = lambda: http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        context=dict(scope='event',session_id='',total_records=1,first_ts=1793491200,last_ts=1793491200,
                     event_counts={'http':1},action_counts={},records=[ROW],anchor=ROW)
        self.app = SimpleNamespace(incident=lambda params: dict(incident=ROW, alerts=[], network=[]),
                                   summary_context=lambda target:context, control=mock.Mock())
        self.body = dict(kind='rule', target=dict(kind='incident', params={'id':'fixture'}))

    def close(self):
        self.server.stop.set()
        self.server.shutdown()
        self.server.server_close()

    def generate(self, body=None):
        output = []
        self.assistant.generate(self.app, 'owner', body or self.body, lambda v: output.append(v) or True, lambda:False)
        return output[-1]['result']

    def test_real_stream_generates_only_observed_rule_and_never_mutates(self):
        result = self.generate()
        validate_rule(result['rule'])
        self.assertIn('http_header:field host;', result['rule'])
        self.assertIn('any any -> any 80', result['rule'])
        self.assertNotIn('192.0.2.1',result['rule'])
        self.assertNotIn('sid:', result['rule'])
        self.assertTrue(self.server.payload['stream'])
        self.assertTrue(self.server.payload['enable_thinking'])
        self.app.control.request.assert_not_called()
        with self.assertRaises(ValueError):
            self.assistant.add(self.app, 'different-owner', result['proposal'])
        self.app.control.request.return_value = {'ok':True, 'job_id':'job'}
        self.assistant.add(self.app, 'owner', result['proposal'])
        self.assistant.add(self.app, 'owner', result['proposal'])
        self.app.control.request.assert_called_once()

    def test_disconnect_aborts_upstream_before_any_token_and_releases_slot(self):
        self.server.stall = True
        disconnected = threading.Event()
        output, errors = [], []
        receiving = threading.Event()
        timeouts = []

        class ObservedConnection(http.client.HTTPConnection):
            def getresponse(self):
                timeouts.append(self.sock.gettimeout())
                receiving.set()
                return super().getresponse()

        self.assistant.connection = lambda: ObservedConnection('127.0.0.1', self.server.server_port, timeout=2)
        def run():
            try:
                self.assistant.generate(self.app, 'owner', self.body, lambda v:output.append(v) or True, disconnected.is_set)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(self.server.entered.wait(2))
        self.assertTrue(receiving.wait(1))
        self.assertEqual(timeouts, [None], 'the dial timeout does not limit inference reads')
        with self.assertRaisesRegex(ValueError, '正在生成'):
            self.generate()
        disconnected.set()
        thread.join(1)
        self.assertFalse(thread.is_alive(), 'client disconnect must return without awaiting generation')
        self.assertTrue(self.server.cancelled.wait(1), 'upstream socket closed before model finishes')
        deadline = time.monotonic()+1
        while not self.assistant.gate.acquire(blocking=False) and time.monotonic()<deadline:
            time.sleep(.01)
        self.assistant.gate.release()
        self.assertFalse(errors)
        self.assertFalse(self.assistant.proposals)
        self.assertFalse(any('result' in item for item in output))

    def test_summary_and_truncated_output(self):
        self.server.text = '事件概述：仅检测到告警，尚不能确认入侵成功。'
        self.assertIn('尚不能确认', self.generate(dict(self.body, kind='summary'))['text'])
        self.server.finish = 'length'
        with self.assertRaisesRegex(ValueError, '不完整'):
            self.generate()

    def test_summary_stream_separates_reasoning_deltas_from_summary_and_tagged_content(self):
        self.server.deltas_for=lambda payload:([{'content':'分析说明：先核对相似连接。\n{"queries":[]}'}] if '狩猎助手' in payload['messages'][0]['content'] else
            [{'reasoning_content':'先核对'},{'reasoning_content':'连接方向。'},{'content':'<thi'},{'content':'nk>tagged reasoning</th'},
             {'content':'ink>分析说'}, {'content':'明：现有证据有限'}, {'content':'。\n通信概览：'}, {'content':'公开正文。'}])
        output=[]
        self.assistant.generate(self.app,'owner',dict(self.body,kind='summary'),lambda item:output.append(item) or True,lambda:False)
        public=''.join(item.get('delta','') for item in output)
        self.assertEqual(public,'通信概览：公开正文。');self.assertEqual(output[-1]['result']['text'],public)
        notes=[item['analysis_delta'] for item in output if 'analysis_delta' in item]
        self.assertEqual(notes,['先核对相似连接。','现有证据有限','。'])
        self.assertEqual([item['reasoning_delta'] for item in output if 'reasoning_delta' in item], ['先核对','连接方向。'])
        self.assertNotIn('tagged reasoning',json.dumps(output));self.assertNotIn('queries',public)
        first=next(index for index,item in enumerate(output) if 'delta' in item)
        self.assertTrue(output[first-1]['analysis_done'])
        self.assertTrue(all(index < first-1 for index,item in enumerate(output) if 'reasoning_delta' in item))
        self.assertTrue(all(payload['enable_thinking'] for payload in self.server.payloads))
        stream=VisibleText();self.assertEqual(stream.feed('a<analysis>hidden'), 'a')
        self.assertEqual(stream.feed('</analysis>b',final=True),'b')

    def test_partial_body_arrives_before_completion_and_disconnect_cancels(self):
        self.server.stream_prefix=True
        self.server.response_for=lambda payload:'{"queries":[]}' if '狩猎助手' in payload['messages'][0]['content'] else '通信概览：正在逐步输出可见的测试正文。'
        disconnected=threading.Event();received=threading.Event();output=[];errors=[]
        def send(item):
            output.append(item)
            if 'delta' in item:received.set()
            return True
        def run():
            try:self.assistant.generate(self.app,'owner',dict(self.body,kind='summary'),send,disconnected.is_set)
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=run);thread.start()
        try:
            self.assertTrue(received.wait(3));self.assertTrue(thread.is_alive())
            self.assertFalse(any('result' in item for item in output))
            disconnected.set();thread.join(1)
            self.assertFalse(thread.is_alive());self.assertTrue(self.server.cancelled.wait(1))
            self.assertFalse(errors);self.assertFalse(self.assistant.proposals)
        finally:disconnected.set();self.server.stream_prefix=False;thread.join(2)

    def test_rule_action_is_explicit_and_defaults_to_alert(self):
        self.assertTrue(self.generate()['rule'].startswith('alert '))
        result=self.generate(dict(self.body,action='block'))
        self.assertTrue(result['rule'].startswith('block '));validate_rule(result['rule'])
        with self.assertRaisesRegex(ValueError,'动作无效'):
            self.generate(dict(self.body,action='drop; lua:evil'))
        self.app.control.request.assert_not_called()

    def test_invalid_choice_and_option_injection_are_rejected_or_encoded_as_text(self):
        choices = candidates([ROW])
        for value in (-1, 4, '0', True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rule_from_choice(dict(candidate=value), choices)
        result = rule_from_choice(dict(candidate=0, message='evil"; sid:1;)\n drop'), choices)
        validate_rule(result['rule'])
        self.assertNotIn('sid:1;', result['rule'])
        for line in ('drop tcp any any -> any any (sid:1;)', result['rule']+'\n', result['rule'].replace('80 (', '99999 (')):
            with self.assertRaises(ValueError):validate_rule(line)
        self.assertEqual(candidates([dict(ROW, src='any'), dict(ROW, dport=0)]), [])

    def test_empty_evidence_refuses_rule_without_model_call_and_context_stays_json(self):
        self.app.incident = lambda params:dict(incident={'sig':'No tuple'}, alerts=[], network=[])
        self.app.summary_context=lambda target:dict(records=[],anchor={})
        self.assertTrue(self.generate()['unavailable'])
        self.assertFalse(self.server.entered.is_set())
        data = dict(records=[dict(ROW, sig='x'*100) for _ in range(30)])
        payload = prompt_payload('rule', data, candidates([ROW]))
        decoded = json.loads(payload['messages'][1]['content'])
        self.assertEqual(decoded['candidates'][0]['host'], 'example.test')
        self.assertLessEqual(sum(len(m['content'].encode()) for m in payload['messages']),1500)


if __name__ == '__main__':
    unittest.main()
