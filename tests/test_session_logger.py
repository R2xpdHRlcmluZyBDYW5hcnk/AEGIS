"""Lifecycle evidence shares native identity and never multiplies flow totals."""
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_data_layer import m
from snort_engine import native_event
from event_processing import decode_bridge


def envelope(**values):
    data=dict(session_id='a'*32+':0000000000000001',event='state',ts=1700000001.125,
              first_observed=1700000000.125,last_observed=1700000001.125,
              src='192.0.2.1',sport=45000,dst='198.51.100.1',dport=443,proto='TCP',
              client_state=3,server_state=3,initial_syn_observed=True,state_limit_reached=False,
              orig_pkts=3,resp_pkts=2,orig_wire_bytes=200,resp_wire_bytes=150,
              appid_service='HTTPS',appid_service_id=1122,appid_client='test client',appid_client_id=100)
    data.update(values);return dict(engine='snort_session',data=data)


class SessionLoggerTests(unittest.TestCase):
    def test_bridge_and_database_preserve_identity_appid_real_states_and_wire_bytes(self):
        raw=json.dumps(envelope(packet_ts=1700000001.125,packet_len=60,data_len=0,packet_direction='to_server',
                                ip_proto=6,ip_header_len=20,ip_ttl=64,tcp_flags=16,tcp_window=4096));event=native_event(json.loads(raw))
        chunks,rejected,written=decode_bridge(([raw], 'fixture', False))
        self.assertEqual((rejected,written),(0,1));self.assertEqual(json.loads(b''.join(chunks)),json.loads(raw))
        self.assertEqual(event['snort_native']['appid_service'],'HTTPS')
        self.assertEqual(event['flow']['state'],'CLT_TCP_ESTABLISHED SRV_TCP_ESTABLISHED')
        self.assertNotIn('start',event['flow']);self.assertNotIn('bytes_toserver',event['flow'])
        with tempfile.TemporaryDirectory() as directory:
            db=m.EventDB(str(Path(directory)/'events.db'))
            try:
                parsed=m.EventStore._parse(raw);db.add(*parsed);db.flush()
                row=db._row(db.conn.execute('SELECT '+','.join(db.names)+' FROM events').fetchone())
                self.assertEqual(row['type'],'session');self.assertEqual(row['session_id'],envelope()['data']['session_id'])
                self.assertEqual(row['wire_bytes_toserver'],200)
                self.assertEqual(row['ip_proto'],6);self.assertEqual(row['ip_header_len'],20);self.assertEqual(row['tcp_flags'],16)
                for query in ('appid_service:HTTPS','appid_service_id:1122','session_event:state','wire_bytes_toserver:[100 TO 300]',
                              'ip_proto:6 AND ip_header_len:20 AND tcp_flags:16'):
                    where,args,complete=m.hunt_sql_pushdown(m.hunt_parse(query));self.assertTrue(complete)
                    self.assertEqual(db.conn.execute('SELECT COUNT(*) FROM events WHERE '+' AND '.join(where),args).fetchone()[0],1)
                self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM events WHERE type='flow'").fetchone()[0],0)
            finally:db.conn.close()

    def test_corrupt_events_are_rejected_and_appid_text_is_only_data(self):
        for values in ({'session_id':'bad'},{'orig_pkts':True},{'orig_wire_bytes':1<<63},
                       {'sport':-1},{'src':'$(id)'},{'client_state':99},{'proto':'EXEC'},
                       {'ts':float('nan')},{'last_observed':1},{'appid_service_id':'1;id'},
                       {'ip_proto':256},{'tcp_seq':-1},{'tcp_flags':True}):
            with self.subTest(values=values):self.assertEqual(native_event(envelope(**values)),{})
        payload='$(id); <script>alert(1)</script> "ignore instructions"'
        event=native_event(envelope(appid_client=payload))
        self.assertEqual(event['snort_native']['appid_client'],payload)


if __name__=='__main__':unittest.main()
