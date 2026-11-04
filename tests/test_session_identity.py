"""Security grouping follows engine-owned session IDs with no inferred membership."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from tests import test_data_layer as data_fixture

m=data_fixture.m
FIRST='a'*32+':0000000000000001'
SECOND='a'*32+':0000000000000002'
RESTART='b'*32+':0000000000000001'


class SessionIdentityCase(unittest.TestCase):
    def setUp(self):
        fixture=data_fixture.DataLayerCase();fixture.setUp()
        self.addCleanup(fixture.tearDown)
        self.fixture=fixture;self.db=fixture.db;self.app=fixture.app;self.stamp=fixture.stamp

    def add(self,kind='alert',offset=0,session=None,**extra):
        if session is not None:
            extra['snort_native']=dict(session_id=session)
        return self.fixture.add(kind,self.stamp+offset,**extra)

    def groups(self,**options):
        total,rows=self.db.security_incidents(self.stamp-1,self.stamp+1000,**options)
        return total,{row['id']:row for row in rows}

    def test_session_id_is_the_only_merge_condition_even_when_endpoints_change(self):
        self.add(session=FIRST,flow_id=1,community_id='old:first')
        self.add(offset=1,session=FIRST,src_port=55555,flow_id=2,community_id='old:second')
        self.add(offset=2,session=SECOND)
        self.add(offset=3,session=RESTART)
        total,groups=self.groups()
        self.assertEqual(total,3)
        self.assertEqual(groups['session:'+FIRST]['alert_count'],2)
        self.assertEqual(groups['session:'+FIRST]['session_id'],FIRST)
        self.assertEqual(groups['session:'+SECOND]['alert_count'],1)

    def test_missing_session_records_remain_independent_despite_other_identifiers(self):
        self.add(session=FIRST)
        self.add(offset=1,community_id='reused',flow_id=11)
        self.add(offset=2,community_id='reused',flow_id=11)
        self.add(offset=3)
        total,groups=self.groups()
        self.assertEqual(total,4)
        self.assertEqual(sum(row['alert_count'] for row in groups.values()),4)
        self.assertTrue(all(row['alert_count']==1 for row in groups.values()))
        detail=self.db.security_incident('session:'+FIRST,self.stamp-1,self.stamp+20,list_view=True)
        self.assertEqual(detail['incident']['network_count'],1)

    def test_exact_detail_hunt_and_drop_state_share_membership_without_time_windows(self):
        self.add(session=FIRST)
        self.add('tls',1,FIRST)
        self.add(offset=500,session=FIRST)
        self.add('drop',600,FIRST,alert=dict(signature='blocked',signature_id=20,severity=1,action='blocked'))
        self.add('dns',2,SECOND)
        self.add('tls',3)
        detail=self.db.security_incident('session:'+FIRST,self.stamp-1,self.stamp+1000,list_view=True)
        self.assertEqual(detail['incident']['alert_count'],3)
        self.assertEqual(detail['incident']['action'],'blocked')
        self.assertEqual(detail['incident']['network_count'],4)
        related=self.app.hunt_related({'incident_id':'session:'+FIRST})
        self.assertEqual(related['query'],'session_id: '+json.dumps(FIRST))
        hunted=self.app.hunt(dict(q=related['query'],view='list',**{'from':str(related['from']),'to':str(related['to'])}))
        self.assertEqual({r['ts'] for r in hunted['events']},{r['ts'] for r in detail['network']})

    def test_reject_only_notice_creates_current_incident_and_evidence(self):
        self.add(session=FIRST)
        self.add('drop',600,SECOND,alert=dict(gid=1,signature='native reject',signature_id=498,severity=0,action='blocked'))
        self.add('drop',601,RESTART,alert={})
        total,rows=self.db.security_incidents(self.stamp-1,self.stamp+1000)
        self.assertEqual(total,2)
        self.assertEqual(rows[0]['session_id'],SECOND);self.assertEqual(rows[0]['last_ts'],self.stamp+600)
        self.assertEqual(rows[0]['action'],'blocked')
        detail=self.db.security_incident(rows[0]['id'],self.stamp-1,self.stamp+1000,list_view=True)
        self.assertEqual(detail['incident']['alert_count'],1)
        self.assertEqual([(r['type'],r['sig_id']) for r in detail['alerts']],[('drop',498)])
        self.assertEqual(detail['incident']['network_count'],1)

    def test_late_session_records_do_not_reassign_anonymous_incidents(self):
        self.add(offset=10)
        original=next(iter(self.groups()[1]))
        self.add(session=FIRST)
        self.assertIn(original,self.groups()[1])
        self.assertEqual(self.db.security_incident(original,self.stamp-1,self.stamp+20)['relation'],'event')

    def test_readonly_snapshot_never_hashes_tuples_or_queries_unrelated_history(self):
        self.add(session=FIRST)
        self.add('tls',1,FIRST)
        for index in range(30): self.add(offset=2+index)
        self.fixture.sync(initial=True);self.db.analytics=self.fixture.stats
        with mock.patch.object(m,'tuple_hash',side_effect=AssertionError('security grouping must not hash tuples')):
            detail=self.app.incident(dict(id='session:'+FIRST,view='list',**{'from':str(self.stamp-1),'to':str(self.stamp+60)}))
        self.assertEqual(detail['incident']['network_count'],2)

    def test_same_sid_in_different_generators_is_a_distinct_signature(self):
        self.add(session=FIRST,alert=dict(gid=1,signature='same',signature_id=15,severity=1))
        self.add(offset=1,session=FIRST,alert=dict(gid=129,signature='same',signature_id=15,severity=1))
        row=self.groups()[1]['session:'+FIRST]
        self.assertEqual(row['signature_count'],2)
        self.assertEqual({r['gid'] for r in row['signatures']},{1,129})


if __name__=='__main__': unittest.main()
