"""Distinguish useful lifecycle observations from repeated and reopened evidence."""
import json
import unittest
from tests.analyze_collection import analyze


class CollectionAnalysisCase(unittest.TestCase):
    def session(self,event,stamp=1,**fields):
        return json.dumps(dict(engine='snort_session',data=dict(session_id='fixture',event=event,ts=stamp,
            client_state=fields.pop('client_state',1),server_state=1,orig_pkts=fields.pop('orig_pkts',1),
            resp_pkts=0,orig_wire_bytes=84,resp_wire_bytes=0,**fields))).encode()+b'\n'

    def test_state_changes_and_active_snapshots_are_not_redundant(self):
        raw=self.session('start')+self.session('state',2,client_state=2)+self.session('update',32,client_state=2,orig_pkts=4)+self.session('end',33,client_state=2,orig_pkts=4)
        result=analyze([raw])
        self.assertEqual(result['redundant_events'],{})
        self.assertEqual(result['events_after_end'],0)
        self.assertEqual(result['sample_sessions'],1)

    def test_late_observation_after_end_and_unchanged_state_are_reported(self):
        raw=self.session('first_observed')+self.session('state',2)+self.session('end',3)+self.session('first_observed',3)
        result=analyze([raw])
        self.assertEqual(result['redundant_events'],{'same_state':1})
        self.assertEqual(result['duplicate_starts'],1)
        self.assertEqual(result['events_after_end'],1)

    def test_anomalies_without_identity_do_not_collapse_into_one_session(self):
        def row(identity):return json.dumps(dict(kind='weird',data=dict(session_id=identity,ts=1,gid=129,sid=12,msg='fixture'))).encode()+b'\n'
        result=analyze([row('one')*3+row('two')+row('')*2+b'incomplete'])
        self.assertEqual(result['weird_records'],6)
        self.assertEqual(result['weird_session_signatures'],2)
        self.assertEqual(result['max_same_weird_per_session'],3)
        self.assertEqual(result['weird_records_without_session'],2)
        self.assertEqual(result['partial_or_invalid_lines'],1)
        self.assertNotIn('fixture',json.dumps(result))


if __name__=='__main__':unittest.main()
