import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import snort_engine
import snort_rules

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class NativeEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = load('native_test_web', ROOT/'ips-web')

    def envelope(self, **values):
        return dict(engine='snort3', epoch='fixture', data=dict(
            ts=1700000000.125, uid=18446744073709551615,
            **{'id.orig_h':'192.0.2.1','id.orig_p':45000,'id.resp_h':'198.51.100.1','id.resp_p':443},
            **values))

    def test_native_uid_is_lossless_in_database_and_query(self):
        envelope=self.envelope(duration=5,orig_pkts=4,resp_pkts=3,orig_bytes=12,resp_bytes=8,proto='TCP',service='ssl',conn_state='CLT_TCP_ESTABLISHED SRV_TCP_ESTABLISHED',history='hADd')
        parsed=self.web.EventStore._parse(json.dumps(envelope))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0]['native_uid'],'18446744073709551615')
        with tempfile.TemporaryDirectory() as directory:
            db=self.web.EventDB(str(Path(directory)/'events.db'))
            try:
                db.add(parsed[0],parsed[1]);db.flush()
                row=db._row(db.conn.execute('SELECT '+','.join(db.names)+' FROM events').fetchone())
                self.assertEqual(row['native_uid'],'18446744073709551615')
                identifier,key=db.conn.execute('SELECT id,event_key FROM events').fetchone()
                self.assertEqual(db.read_record(str(identifier)+':'+key)['raw_text'],json.dumps(envelope))
                predicate=self.web.hunt_parse('uid:18446744073709551615')
                where,args,complete=self.web.hunt_sql_pushdown(predicate,False)
                self.assertTrue(complete)
                self.assertTrue(db.conn.execute('SELECT 1 FROM events WHERE '+' AND '.join(where),args).fetchone())
                self.assertFalse(self.web.hunt_match(self.web.hunt_parse('uid:18446744073709551614'),row,False))
            finally:
                db.conn.close()

    def test_native_dns_string_answer_remains_one_answer(self):
        event=snort_engine.native_event(self.envelope(trans_id=1234,query='example.test',qtype_name='A',rcode_name='NOERROR',answers='198.51.100.1'))
        self.assertEqual(event['dns']['answers'],[{'rdata':'198.51.100.1'}])

    def test_http_upload_size_is_indexed_and_searchable_without_body_content(self):
        raw=json.dumps(self.envelope(trans_depth=1,method='POST',host='example.test',uri='/upload',
            request_body_len=8192,response_body_len=128,version='1.1',status_code=200))
        with tempfile.TemporaryDirectory() as directory:
            db=self.web.EventDB(str(Path(directory)/'events.db'))
            try:
                db.add(*self.web.EventStore._parse(raw));db.flush()
                clauses,args,complete=self.web.hunt_sql_pushdown(self.web.hunt_parse('http_request_bytes:>8000'))
                self.assertTrue(complete)
                row=db.conn.execute('SELECT http_request_bytes,clen FROM events WHERE '+' AND '.join(clauses),args).fetchone()
                self.assertEqual(row,(8192,128))
                self.assertNotIn('payload',json.loads(raw)['data'])
            finally:db.conn.close()

    def test_deferred_conn_log_time_does_not_invent_packet_time_bounds(self):
        envelope=self.envelope(duration=5,orig_pkts=4,resp_pkts=3,proto='TCP',service='unknown')
        normalized=snort_engine.native_event(envelope)
        self.assertNotIn('start',normalized['flow']);self.assertNotIn('end',normalized['flow'])
        self.assertEqual(normalized['flow']['age'],5)
        m=self.web
        with tempfile.TemporaryDirectory() as directory:
            db=m.EventDB(str(Path(directory)/'events.db'))
            try:
                db.add(*m.EventStore._parse(json.dumps(envelope)));db.flush()
                # A previous version persisted trigger-time-derived bounds.
                db.conn.execute('UPDATE events SET flow_start=1700000000,flow_end=1700000005');db.conn.commit()
                row=db.conn.execute('SELECT '+','.join(db.names)+' FROM events').fetchone()
                self.assertNotIn('flow_start',db._row(row));self.assertNotIn('flow_end',db._row(row))
                self.assertNotIn('flow_start',db._row_lite(row,{'flow_start'}))
                for field in ('flow_start','flow_end'):
                    where,args,complete=m.hunt_sql_pushdown(m.hunt_parse(field+':>0'))
                    self.assertTrue(complete)
                    self.assertEqual(db.conn.execute('SELECT COUNT(*) FROM events WHERE '+' AND '.join(where),args).fetchone()[0],0)
            finally:db.conn.close()

    def test_passive_would_block_is_not_reported_as_an_actual_block(self):
        raw=self.envelope(sid=1,gid=1,rev=1,msg='fixture',action='would_block',ips_action='block',proto='TCP')
        event=snort_engine.native_event(raw,metadata={})
        self.assertEqual(event['event_type'],'alert')
        self.assertEqual(event['alert']['action'],'allowed')
        raw['data']['action']='block'
        event=snort_engine.native_event(raw,metadata={})
        self.assertEqual(event['event_type'],'drop')
        self.assertEqual(event['alert']['action'],'blocked')

    def test_native_schema_exposes_supported_fields(self):
        fields={f['name'] for f in self.web.App.hunt_schema()['fields']}
        self.assertTrue({'uid','cipher','history','command','fuid'} <= fields)
        self.assertTrue(fields.isdisjoint({'ja3','ja4','community_id','md5','sha1'}))

    def test_invalid_native_records_do_not_become_epoch_events(self):
        for stamp in (None,0,float('inf'),'bad'):
            item=self.envelope(sid=1,gid=1,rev=1)
            item['data']['ts']=stamp
            self.assertIsNone(self.web.EventStore._parse(json.dumps(item).encode()))


class RulePolicyTests(unittest.TestCase):
    def test_disable_group_and_explicit_reject_are_applied_to_candidate_only(self):
        text='alert tcp any any -> any 80 (msg:"fixture"; sid:1; rev:1;)\nalert udp any any -> any 53 (msg:"DNS"; sid:2; rev:1;)\n'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'disable.conf').write_text('group:http\n')
            (root/'action-override.conf').write_text('reject sid:2\n')
            output=snort_rules.apply_policy(text,root,{'1':{'http'},'2':{'dns'}})
            self.assertTrue(output.startswith('# alert tcp'))
            self.assertIn('\nreject udp',output)
            self.assertTrue(text.startswith('alert tcp'))

    def test_ui_drop_policy_uses_native_flow_block(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'drop.conf').write_text('sid:1\n')
            output=snort_rules.apply_policy('alert ip any any -> any any (sid:1;)\n',directory,{})
            self.assertTrue(output.startswith('block ip'))

    def test_rulesets_enable_and_disable_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            snort_rules.set_source(directory,'snort/community',True)
            snort_rules.set_source(directory,'snort/registered',True)
            self.assertEqual(snort_rules.enabled_sources(directory),{'snort/community','snort/registered'})
            snort_rules.set_source(directory,'snort/community',False)
            self.assertEqual(snort_rules.enabled_sources(directory),{'snort/registered'})



class BridgeTests(unittest.TestCase):
    def test_fast_copytruncate_regrowth_is_detected_after_checkpoint_restart(self):
        module=load('rotated_bridge_test',ROOT/'ips-event-bridge')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);logs=root/'logs';logs.mkdir()
            instance=root/'instance.json';instance.write_text('{"epoch":"fixture","started":0}')
            source=logs/'0_file_connector_ndr_transmit'
            source.write_text(json.dumps(dict(ts=1700000000,uid=1,trans_id=1,query='before.example.test'))+'\n')
            args=(logs,root/'events.json',root/'checkpoint.json',instance)
            bridge=module.Bridge(*args);self.assertEqual(bridge.poll(),1)
            inode=source.stat().st_ino
            source.write_text(''.join(json.dumps(dict(ts=1700000001+i,uid=i+2,trans_id=1,query='after.example.test'))+'\n' for i in range(10)))
            self.assertEqual(source.stat().st_ino,inode)
            restored=module.Bridge(*args);self.assertEqual(restored.poll(),10)
            self.assertEqual(module.Bridge(*args).poll(),0)
            self.assertEqual(len((root/'events.json').read_text().splitlines()),11)

    def test_decoder_alerts_before_flow_creation_are_ingested_without_duplicate_notices(self):
        module=load('decoder_bridge_test',ROOT/'ips-event-bridge')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);logs=root/'logs';logs.mkdir()
            instance=root/'instance.json';instance.write_text('{"epoch":"fixture","started":0}')
            event=dict(seconds=1700000000,timestamp='11/14-22:13:20.125000',gid=116,sid=6,rev=1,
                       msg='IPv4 datagram length > captured length',proto='IP',action='allow',priority=3)
            (logs/'0_alert_json.txt').write_text(json.dumps(event)+'\n'+json.dumps(dict(event,gid=1))+'\n')
            bridge=module.Bridge(logs,root/'events.json',root/'checkpoint.json',instance)
            self.assertEqual(bridge.poll(),1)
            envelope=json.loads((root/'events.json').read_text())
            normalized=snort_engine.native_event(envelope,metadata={})
            self.assertEqual(normalized['event_type'],'alert')
            self.assertEqual(normalized['alert']['severity'],3)
            self.assertTrue(normalized['timestamp'].endswith('.125000+00:00'))

    def test_partial_line_restart_and_truncation(self):
        module=load('native_bridge_test',ROOT/'ips-event-bridge')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);logs=root/'logs';logs.mkdir()
            instance=root/'instance.json';instance.write_text('{"epoch":"fixture","started":0}')
            source=logs/'0_file_connector_ndr_transmit'
            record=json.dumps({'ts':1700000000,'uid':1,'trans_id':1,'query':'example.test'})
            source.write_text(record)
            args=(logs,root/'events.json',root/'checkpoint.json',instance)
            bridge=module.Bridge(*args)
            self.assertEqual(bridge.poll(),0)
            with source.open('a') as output: output.write('\n')
            self.assertEqual(bridge.poll(),1)
            restarted=module.Bridge(*args)
            self.assertEqual(restarted.poll(),0)
            source.write_text(record.replace('example.test','x.test')+'\n')
            self.assertEqual(restarted.poll(),1)
            records=[json.loads(line) for line in (root/'events.json').read_text().splitlines()]
            self.assertEqual([r['data']['query'] for r in records],['example.test','x.test'])


if __name__ == '__main__':
    unittest.main()
