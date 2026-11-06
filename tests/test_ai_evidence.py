"""DNS candidates, IOC boundaries, protocol rules and raw-alert CSV regression."""
import csv
import io
import json
import unittest

from tests import test_llm_context as fixture
from llm_assistant import candidates,rule_from_choice,summary_payload,select_hunts

m=fixture.m


class EvidenceTests(unittest.TestCase):
    setUp=fixture.SessionContextTests.setUp
    add=fixture.SessionContextTests.add
    target=fixture.SessionContextTests.target

    def dns(self,name='normal.example.test',age=10,ttl=60,client='192.0.2.1',answer='198.51.100.2'):
        self.fixture.add('dns',self.stamp-age,src_ip=client,dest_ip='198.51.100.53',proto='UDP',alert={},
            snort_native=dict(session_id=fixture.SECOND,dns_ttl=ttl),dns=dict(rrname=name,answers=[dict(rdata=answer)]))

    def test_dns_match_requires_client_answer_time_and_ttl_and_keeps_independent_session(self):
        self.add('tls',0,tls=dict(sni='normal.example.test'))
        self.dns();self.dns('expired.example.test',age=80,ttl=60)
        self.dns('other-client.example.test',client='192.0.2.99');self.dns('wrong-ip.example.test',answer='198.51.100.3')
        result=self.app.summary_dns_context(dict(session_id=fixture.FIRST))
        self.assertEqual([row['name'] for row in result['records']],['normal.example.test'])
        clue=result['records'][0];self.assertEqual(clue['relation'],'candidate');self.assertEqual(clue['session_id'],fixture.SECOND)
        self.assertEqual(self.app.record({'key':clue['record_id']})['record']['dns'],'normal.example.test')
        context=self.app.summary_context(self.target());context['dns_clues']=result
        payload,_=summary_payload(context)
        data=json.loads(payload['messages'][1]['content']);self.assertEqual(data['dns_hint']['name'],'normal.example.test')
        self.assertEqual(context['total_records'],1)

    def test_structured_plan_compiles_numeric_comparisons_and_escapes_literal_text(self):
        checks=[
            {'terms':[['type','=','drop'],['sig','=','Fixture "quoted" AND src:*']]},
            {'terms':[['type','=','flow'],['flow_age','=',0],['bytes_toclient','>',1000000000]]},
        ]
        planned,status=select_hunts(json.dumps({'checks':checks}))
        self.assertEqual(status,'model')
        self.assertEqual(planned[1]['query'],'type:"flow" AND flow_age:0 AND bytes_toclient:>1000000000')
        self.assertEqual(m.hunt_used_fields(m.hunt_parse(planned[0]['query'])), {'type','sig'})
        for invalid in ([['session_id','=','other']], [['src','>','192.0.2.1']], [['flow_age','=',True]],
                        [['bytes_toclient','>',"0 OR type:*"]]):
            self.assertEqual(select_hunts(json.dumps({'checks':[{'terms':invalid}]})), ([], 'invalid'))

    def test_behavior_search_can_find_unalerted_traffic_with_different_indicators(self):
        self.add('tls',0,tls=dict(sni='observed.example.test'))
        for offset in (20,21,22):
            self.add('flow',offset,fixture.SECOND,src_ip='192.0.2.99',dest_ip='198.51.100.99',
                     flow=dict(state='closed',bytes_toserver=12000,bytes_toclient=0,pkts_toserver=10,pkts_toclient=0))
        self.add('flow',10000,fixture.RESTART,flow=dict(bytes_toserver=12000,bytes_toclient=0))
        query='type:flow AND bytes_toserver:>10000 AND bytes_toclient:0'
        result=self.app.summary_hunt(dict(target=self.target(),query=query))
        self.assertEqual(result['total'],3);self.assertEqual(len(result['records']),1)
        row=result['records'][0];self.assertEqual(row['src'],'192.0.2.99');self.assertEqual(row['dst'],'198.51.100.99')
        self.assertEqual(result['scope'],'related');self.assertIsNotNone(m.hunt_parse(result['query']))
        self.assertFalse(row.get('sig_id'));self.assertTrue(result['excluded_current_session'])
        self.assertEqual(row['_retained_detections'],0)
        context=self.app.summary_context(self.target());payload,_=summary_payload(context,[result])
        data=json.loads(payload['messages'][1]['content'])
        self.assertTrue(any(row.get('relation')=='candidate_related' and row.get('bytes_toserver')==12000 for row in data['records']))
        self.assertEqual(context['total_records'],1)
        with self.assertRaises(ValueError):self.app.summary_hunt(dict(target=self.target(),query='time:[0 TO *]'))

    def test_anonymous_event_can_search_nearby_metadata_without_merging_identity(self):
        self.add('tls',0,None,tls=dict(sni='anonymous.example.test'))
        _,rows=self.db.search_range(self.stamp-1,self.stamp+1,types=['tls'],list_view=True)
        target=dict(kind='record',key=rows[0]['record_id'])
        self.add('tls',10,fixture.SECOND,tls=dict(sni='anonymous.example.test'))
        context=self.app.summary_context(target);self.assertEqual(context['total_records'],1)
        result=self.app.summary_hunt(dict(target=target,query='sni:"anonymous.example.test"'))
        self.assertEqual(result['total'],1);self.assertFalse(result['excluded_current_session'])
        self.assertNotIn('session_id:',result['query'])
        low, high = result['range']
        hits = self.app.hunt({'q':result['query'],'from':str(low),'to':str(high),'view':'list'})
        self.assertEqual([row['record_id'] for row in hits['events']], [result['records'][0]['record_id']])

    def test_csv_includes_blocked_native_detections_and_excludes_ruleless_drops(self):
        self.add('drop',0,alert=dict(signature='blocked detection',signature_id=77,severity=1,action='blocked'))
        self.add('drop',1,alert=dict(signature='engine drop',signature_id=None,severity=0,action='blocked'))
        params=dict(detection='alerts',format='csv',limit='10000',**{'from':str(self.stamp-1),'to':str(self.stamp+2)})
        result=self.app.events(params);self.assertEqual(result['total'],1)
        rows=list(csv.DictReader(io.StringIO(m.events_csv(result['events']).lstrip('\ufeff'))))
        self.assertEqual(rows[0]['signature'],'blocked detection');self.assertEqual(rows[0]['action'],'blocked')


class RuleFeatureTests(unittest.TestCase):
    def test_rules_use_real_protocol_features_and_encode_untrusted_uri_bytes(self):
        base=dict(src='192.0.2.1',dst='198.51.100.2',dport=80,proto='TCP')
        rows=[dict(base,host='example.test',method='GET',url='/danger/"; sid:1;?secret=hidden'),
              dict(base,dport=443,sni='example.test'),dict(base,dport=53,proto='UDP',dns='example.test'),
              dict(base,tcp_flags=3,ip_ttl=32,tcp_window=1024,data_len=0),
              dict(base,appid_payload='Specific Test Application')]
        for row in rows:
            choice=candidates([row]);self.assertEqual(len(choice),1)
            result=rule_from_choice(dict(candidate=0,extra=['ttl','window'] if choice[0]['kind']=='tcp_flags' else []),choice)
            self.assertNotIn('192.0.2.1',result['rule']);self.assertNotIn('hidden',result['rule']);self.assertNotIn('sid:1;',result['rule'])
        self.assertEqual(candidates([base]),[])
        self.assertEqual(candidates([dict(base,tcp_flags=16)]),[])


if __name__=='__main__':unittest.main()
