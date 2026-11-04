"""Every chart counts the same retained log cohort and exact session identities."""
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_network_visibility import backend as m
from tests.test_session_logger import envelope


class OverviewCohortTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=m.EventDB(str(Path(self.temp.name)/'events.db'));self.addCleanup(self.db.conn.close)
        self.low,self.high=1700000000,1700001000;self.raw=[]
        self.ids={name:name*32+':0000000000000001' for name in 'abc'}
        self.add('dns','a',dns=dict(rrname='example.test',type='request'))
        self.add('flow','a',flow=dict(bytes_toserver=120,bytes_toclient=240,pkts_toserver=3,pkts_toclient=2))
        for _ in range(45):self.add('http','b',http=dict(hostname='example.test',http_method='GET',url='/'))
        self.add('flow','b',app_proto='unknown',flow=dict(bytes_toserver=500,bytes_toclient=1000,pkts_toserver=5,pkts_toclient=8))
        for _ in range(30):self.add('alert','c',alert=dict(signature='fixture',signature_id=123,severity=1,action='allowed'))
        # An initial unclassified observation must not make an identified
        # HTTP connection appear in the unknown-application cohort.
        raw=envelope(session_id=self.ids['b'],ts=self.low+1,first_observed=self.low+1,last_observed=self.low+1,
                     appid_service='',appid_service_id=0,event='first_observed')
        self.db.add(*m.EventStore._parse(json.dumps(raw)));self.db.flush()

    def add(self,kind,identity,**extra):
        source={'a':'192.0.2.10','b':'192.0.2.20','c':'192.0.2.30'}[identity]
        row=dict(timestamp=m.iso(self.low+len(self.raw)+10),event_type=kind,src_ip=source,dest_ip='198.51.100.1',
                 src_port=45000,dest_port=53 if identity=='a' else 443,proto='UDP' if identity=='a' else 'TCP',
                 app_proto='dns' if identity=='a' else 'http' if identity=='b' else '',
                 snort_native=dict(session_id=self.ids[identity]))
        row.update(extra);parsed=m.EventStore._parse(json.dumps(row));self.db.add(*parsed);self.db.flush();self.raw.append(parsed[0])

    def summary(self,**params):
        return m.EventDB.compute_network_summary(self.db.conn,self.low,self.high,push=m.App._overview_push(params,self.low,self.high))

    def test_log_address_ranks_count_protocol_logs_and_connection_sources_deduplicate_alerts(self):
        result=self.summary()
        self.assertEqual(result['log_sources'][0]['ip'],'192.0.2.20')
        self.assertEqual({r['ip']:r['count'] for r in result['sources']},dict.fromkeys(('192.0.2.10','192.0.2.20','192.0.2.30'),1))
        self.assertEqual(result['flows'],len(self.ids))
        self.assertEqual(sum(r['count'] for r in result['protocols']),result['flows'])

    def test_dns_and_type_filters_retain_udp_connection_evidence(self):
        for params in (dict(dns='example.test'),dict(type='dns'),dict(dns='example.test',proto='UDP')):
            with self.subTest(params=params):
                result=self.summary(**params)
                self.assertEqual(result['flows'],1);self.assertEqual(result['protocols'],[dict(name='UDP',count=1)])
                self.assertEqual(result['bytes'],360);self.assertEqual(result['bidirectional'],1)
                self.assertEqual({r['name'] for r in result['event_types']},{'dns','flow'})
        self.assertEqual(self.summary(dns='example.test',proto='TCP')['records'],0)

    def test_unknown_application_does_not_select_initial_empty_names_from_identified_connections(self):
        result=self.summary(app='')
        self.assertEqual(result['flows'],1)
        self.assertEqual({r['ip'] for r in result['sources']},{'192.0.2.30'})
        result=self.summary(app='HTTP');self.assertEqual(result['flows'],1)
        self.assertEqual(result['applications'],[dict(name='http',count=1)])

    def test_projection_and_main_database_return_identical_log_and_connection_statistics(self):
        stats=m.StoredNetworkStats(self.db)
        import sqlite3
        projection=sqlite3.connect(':memory:');self.addCleanup(projection.close);stats.install(projection)
        stats.sync(self.db.conn,projection,initial=True,batch=1024)
        direct=self.summary();cached=stats.aggregate(projection,self.low,self.high)
        direct.pop('as_of');cached.pop('as_of');self.assertEqual(cached,direct)

    def test_rolling_cohort_cache_keys_do_not_change_with_each_clock_tick(self):
        snapshots=m.NetworkSnapshots(self.db);self.addCleanup(snapshots.close)
        push=m.App._overview_push(dict(dns='example.test'),('range','start'),('range','end'))
        snapshots.get(self.low,self.high,rolling=True,push=push)
        previous=list(snapshots.entries)
        snapshots.get(self.low+1,self.high+1,rolling=True,push=push)
        self.assertEqual(list(snapshots.entries),previous)

    def test_injection_cannot_escape_cohort_values_and_unidentified_logs_are_not_joined_by_tuple(self):
        self.assertEqual(self.summary(dns="' OR 1=1 --")['records'],0)
        raw=dict(timestamp=m.iso(self.low+1),event_type='dns',src_ip='192.0.2.10',dest_ip='198.51.100.1',proto='UDP',dns=dict(rrname='unrelated.test'))
        self.db.add(*m.EventStore._parse(json.dumps(raw)));self.db.flush()
        result=self.summary(dns='unrelated.test');self.assertEqual(result['records'],1);self.assertEqual(result['flows'],0)


if __name__=='__main__':unittest.main()
