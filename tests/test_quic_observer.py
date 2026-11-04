"""Decoder identity, visible path changes and bounded passive evidence."""
import csv
import io
import json
import unittest

import quic_observer as q
from tests import test_data_layer as fixture_module
m=fixture_module.m


def row(frame=1,connection=0,reverse=False,port=45000,hello=False,dcid=None,scid=None):
    client=('192.0.2.10',port);server=('198.51.100.20',443)
    src,dst=(server,client) if reverse else (client,server)
    fields=dict(zip(q.FIELDS,['']*len(q.FIELDS)))
    fields.update({'frame.number':str(frame),'frame.time_epoch':str(1700000000+frame),
                   'ip.src':src[0],'udp.srcport':str(src[1]),'ip.dst':dst[0],'udp.dstport':str(dst[1]),
                   'udp.length':'108','quic.connection.number':str(connection),
                   'quic.dcid':dcid or ('aa'*8 if reverse else 'bb'*8),
                   'quic.scid':scid or ('bb'*8 if reverse else 'aa'*8),
                   'quic.version':'0x00000001',
                   'tls.handshake.type':'1' if hello else '',
                   'tls.handshake.extensions_server_name':'example.test' if hello else '',
                   'tls.handshake.extensions_alpn_str':'h3' if hello else ''})
    out=io.StringIO();csv.writer(out,delimiter='\t',quoting=csv.QUOTE_ALL,lineterminator='').writerow(fields[k] for k in q.FIELDS)
    return out.getvalue()


class ObserverTests(unittest.TestCase):
    def tracker(self,**kwargs):
        self.events=[]
        return q.Tracker(lambda value:self.events.append(json.loads(json.dumps(value))),**kwargs)

    def test_visible_cid_port_change_keeps_decoder_identity_and_handshake_facts(self):
        tracker=self.tracker()
        for item in (row(hello=True),row(frame=2,reverse=True),row(frame=3,port=45001)):
            tracker.observe(q.packet(item))
        tracker.close();last=self.events[-1]
        self.assertEqual(len({event['data']['session_id'] for event in self.events}),1)
        self.assertEqual(len(last['data']['paths']),2)
        result=q.normalized_event(last)
        self.assertEqual(result['tls']['sni'],'example.test')
        self.assertEqual(result['tls']['client_alpns'],['h3'])
        self.assertEqual(result['app_proto'],'quic')
        self.assertEqual(result['flow']['pkts_toserver'],2)
        self.assertEqual(result['flow']['pkts_toclient'],1)
        self.assertTrue(result['quic']['partial'])

    def test_distinct_decoder_sessions_and_reset_blocks_never_merge_by_tuple(self):
        tracker=self.tracker()
        for item in (row(hello=True),row(frame=2,connection=1,hello=True),row(frame=q.RESET_PACKETS+1,hello=True)):
            tracker.observe(q.packet(item))
        self.assertEqual(len({event['data']['session_id'] for event in self.events}),3)
        tracker.observe(q.packet(row(frame=1)))
        self.assertEqual(len({event['data']['session_id'] for event in self.events}),4)

    def test_non_quic_first_frame_marker_prevents_alias_after_decoder_reset(self):
        tracker=self.tracker()
        tracker.observe(q.packet(row(frame=2,hello=True)))
        tracker.observe(q.packet(row(frame=3)))
        marker=q.packet(row(frame=1,connection=''))
        self.assertIsNone(marker['connection']);tracker.observe(marker)
        tracker.observe(q.packet(row(frame=5,hello=True)))
        self.assertEqual(len({event['data']['session_id'] for event in self.events}),2)
        self.assertTrue(any(event['data']['reason']=='decoder_state_reset' for event in self.events))
        self.assertEqual(len(tracker.states),1)

    def test_state_and_path_limits_are_enforced(self):
        tracker=self.tracker(capacity=2)
        for index in range(12):tracker.observe(q.packet(row(frame=index+1,port=45000+index,hello=index==0)))
        self.assertEqual(len(tracker.states),1)
        self.assertEqual(len(next(iter(tracker.states.values()))['paths']),8)
        self.assertTrue(next(iter(tracker.states.values()))['limited'])
        tracker.observe(q.packet(row(frame=20,connection=1)))
        tracker.observe(q.packet(row(frame=21,connection=2)))
        self.assertEqual(len(tracker.states),2)
        self.assertTrue(any(e['data']['reason']=='state_capacity' for e in self.events))

    def test_ambiguous_decoder_connections_are_not_guessed(self):
        self.assertIsNone(q.packet(row(connection='0,1'))['connection'])
        with self.assertRaises(ValueError):q.packet(row(dcid='invalid-cid'))

    def test_unobserved_client_hello_does_not_invent_client_byte_metrics(self):
        tracker=self.tracker();tracker.observe(q.packet(row()));tracker.close()
        result=q.normalized_event(self.events[-1])
        self.assertNotIn('flow',result)
        self.assertEqual(result['quic']['alpn_offered'],[])

    def test_bridge_and_database_preserve_observer_evidence_without_inflating_flow_totals(self):
        tracker=self.tracker();tracker.observe(q.packet(row(hello=True)));tracker.observe(q.packet(row(frame=2,reverse=True)));tracker.close()
        from event_processing import decode_bridge
        lines=[json.dumps(value).encode() for value in self.events]
        segments,rejected,count=decode_bridge((lines,'native-epoch',False))
        self.assertEqual(rejected,0);self.assertEqual(count,len(lines))
        fixture=fixture_module.DataLayerCase();fixture.setUp();self.addCleanup(fixture.tearDown)
        for line in b''.join(segments).splitlines():fixture.db.add(*m.EventStore._parse(line.decode()))
        fixture.db.flush()
        session=self.events[-1]['data']['session_id']
        data=fixture.app.session_events(dict(session_id=session))
        self.assertEqual(data['total'],len(lines))
        latest=fixture.db.read_record(data['events'][0]['record_id'])
        self.assertEqual(latest['record']['observer'],'Wireshark QUIC')
        self.assertTrue(latest['raw_text'])
        self.assertEqual(fixture.db.conn.execute("SELECT COUNT(*) FROM events WHERE type='flow'").fetchone()[0],0)
        self.assertEqual(fixture.db.session_context(session)['records'][0]['type'],'quic')

    def test_live_decoder_reads_a_pipe_and_does_not_write_a_capture_file(self):
        command=q.command(pcap='-')
        self.assertEqual(command[command.index('-r')+1],'-')
        self.assertNotIn('-w',command)
        self.assertIn('-M',command)


if __name__=='__main__':unittest.main()
