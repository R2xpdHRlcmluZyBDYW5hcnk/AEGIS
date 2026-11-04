"""Sparse native logs, bounded malformed records and checkpoint recovery."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from parallel_cpu import CPUExecutor

ROOT=Path(__file__).resolve().parents[1]


class BridgeRecoveryCase(unittest.TestCase):
    def setUp(self):
        loader=importlib.machinery.SourceFileLoader('bridge_recovery',str(ROOT/'ips-event-bridge'))
        self.m=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(self.m)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.logs=self.root/'logs';self.logs.mkdir()
        self.source=self.logs/'0_file_connector_ndr_transmit'
        self.instance=self.root/'instance.json';self.instance.write_text('{"epoch":"fixture","started":0}')
        self.args=(self.logs,self.root/'events.json',self.root/'checkpoint.json',self.instance)

    @staticmethod
    def record(query='fixture'):
        return (json.dumps(dict(ts=1700000000,uid=1,trans_id=1,query=query))+'\n').encode()

    def rows(self):return [json.loads(line)['data'] for line in (self.root/'events.json').read_text().splitlines()]

    def test_bridge_carries_rule_grade_across_web_filesystem_isolation(self):
        raw=dict(ts=1700000000,uid=1,gid=1,sid=498,rev=11,msg='native reject',action='reset')
        self.source.write_text(json.dumps(raw)+'\n')
        metadata=dict(category='bad-unknown',severity=2,metadata={'mitre_tactic_id':['TA0002']})
        with mock.patch.object(self.m,'rule_metadata',return_value={(1,498):metadata}):
            self.assertEqual(self.m.Bridge(*self.args).poll(),1)
        envelope=json.loads((self.root/'events.json').read_text())
        self.assertEqual(envelope['data'],raw)
        import snort_engine
        with mock.patch.object(snort_engine,'rule_metadata',side_effect=PermissionError('Web cannot read rules')):
            parsed=snort_engine.native_event(envelope)
        self.assertEqual(parsed['alert']['severity'],2)
        self.assertEqual(parsed['alert']['category'],'bad-unknown')
        self.assertEqual(parsed['alert']['metadata']['mitre_tactic_id'],['TA0002'])

    def test_copytruncate_keeps_writer_offset_and_sparse_prefix_does_not_stop_ingestion(self):
        bridge=self.m.Bridge(*self.args);bridge.LINE_LIMIT=256
        with self.source.open('wb') as writer:
            writer.write(self.record()*100);writer.flush()
            self.assertEqual(bridge.poll(),100)
            writer.truncate(0)  # The live Snort writer retains its file offset.
            writer.write(self.record('after-rotation'));writer.flush()
            recovered=self.m.Bridge(*self.args);recovered.LINE_LIMIT=256
            self.assertEqual(recovered.poll(),1)
            self.assertGreater(recovered.sparse_bytes,0)
            self.assertEqual(recovered.rejected,0)
        self.assertEqual(self.rows()[-1]['query'],'after-rotation')
        self.assertEqual(self.m.Bridge(*self.args).poll(),0)

    def test_gap_larger_than_line_limit_has_bounded_fallback_without_seek_data(self):
        self.source.write_bytes(b'\0'*2000+self.record())
        bridge=self.m.Bridge(*self.args);bridge.LINE_LIMIT=128;bridge.BATCH_BYTES=256
        with mock.patch.object(self.m,'sparse_data_position',return_value=None):
            for _ in range(12):bridge.poll()
        self.assertEqual(len(self.rows()),1);self.assertEqual(bridge.rejected,0)
        self.assertEqual(bridge.sparse_bytes,2000)

    def test_oversized_record_is_rejected_once_across_restart_then_next_record_is_read(self):
        raw=b'x'*700+b'\n'+self.record('recovered')
        self.source.write_bytes(raw)
        bridge=self.m.Bridge(*self.args);bridge.LINE_LIMIT=128;bridge.BATCH_BYTES=256
        self.assertEqual(bridge.poll(),0)
        self.assertTrue(next(iter(bridge.files.values()))['discarding'])
        recovered=self.m.Bridge(*self.args);recovered.LINE_LIMIT=128;recovered.BATCH_BYTES=256
        for _ in range(5):recovered.poll()
        self.assertEqual(recovered.rejected,1)
        self.assertEqual(self.rows()[0]['query'],'recovered')
        self.assertEqual(self.source.read_bytes(),raw)

    def test_replaced_file_resets_oversized_record_discard_state(self):
        self.source.write_bytes(b'x'*700)
        bridge=self.m.Bridge(*self.args);bridge.LINE_LIMIT=128;bridge.BATCH_BYTES=256
        bridge.poll()
        replacement=self.logs/'replacement';replacement.write_bytes(self.record('new-file'))
        replacement.replace(self.source)
        self.assertEqual(bridge.poll(),1)
        self.assertEqual(self.rows()[0]['query'],'new-file')

    def test_idle_poll_does_not_sync_or_rewrite_checkpoint(self):
        self.source.write_bytes(self.record())
        bridge=self.m.Bridge(*self.args);bridge.poll()
        before=(self.root/'checkpoint.json').stat().st_mtime_ns
        with mock.patch.object(self.m.os,'fsync',side_effect=AssertionError('idle fsync')):
            self.assertEqual(bridge.poll(),0)
        self.assertEqual((self.root/'checkpoint.json').stat().st_mtime_ns,before)

    def test_failed_output_sync_never_advances_checkpoint(self):
        self.source.write_bytes(self.record('first'))
        bridge=self.m.Bridge(*self.args);bridge.poll()
        before=(self.root/'checkpoint.json').read_bytes()
        with self.source.open('ab') as source:source.write(self.record('second'))
        with mock.patch.object(self.m.os,'fsync',side_effect=OSError('disk failure')):
            with self.assertRaisesRegex(OSError,'disk failure'):bridge.poll()
        self.assertEqual((self.root/'checkpoint.json').read_bytes(),before)
        self.assertEqual(self.m.Bridge(*self.args).poll(),1)
        self.assertEqual(self.rows()[-1]['query'],'second')

    def test_torn_output_tail_is_recovered_from_native_source(self):
        self.source.write_bytes(self.record('first'))
        self.m.Bridge(*self.args).poll()
        with (self.root/'events.json').open('ab') as output:output.write(b'{"partial')
        with self.source.open('ab') as source:source.write(self.record('second'))
        raw=self.source.read_bytes()
        bridge=self.m.Bridge(*self.args);self.assertEqual(bridge.poll(),1)
        self.assertEqual([r['query'] for r in self.rows()],['first','second'])
        self.assertEqual(self.source.read_bytes(),raw)

    def test_notice_batch_reuses_one_metadata_snapshot(self):
        row=dict(ts=1700000000,uid=1,gid=1,sid=498,rev=1,msg='notice',action='reset')
        self.source.write_text((json.dumps(row)+'\n')*3)
        with mock.patch.object(self.m,'rule_metadata',return_value={}) as read:
            self.assertEqual(self.m.Bridge(*self.args).poll(),3)
            read.assert_called_once()

    def test_parallel_batches_match_serial_envelopes_and_preserve_source(self):
        raw=b''.join(self.record(str(i)+'x'*1800) for i in range(4096))
        self.source.write_bytes(raw)
        serial=self.m.Bridge(self.logs,self.root/'serial.json',self.root/'serial.state',self.instance)
        parallel=self.m.Bridge(*self.args)
        serial.cpu=CPUExecutor(1);parallel.cpu=CPUExecutor(4)
        pids=set()
        try:
            for bridge in (serial,parallel):
                for _ in range(10):
                    count=bridge.poll()
                    if bridge is parallel:pids.update(bridge.worker_pids)
                    if not count:break
            self.assertEqual((self.root/'events.json').read_bytes(),(self.root/'serial.json').read_bytes())
            self.assertEqual(self.source.read_bytes(),raw)
            if parallel.cpu.workers>1:self.assertGreater(len(pids),1)
        finally:serial.cpu.close();parallel.cpu.close()

    def test_worker_failure_after_one_output_batch_retains_source_progress(self):
        self.source.write_bytes(self.record('first'))
        bridge=self.m.Bridge(*self.args);bridge.poll()
        before=(self.root/'checkpoint.json').read_bytes()
        with self.source.open('ab') as source:
            source.write(b''.join(self.record(str(i)+'x'*1800) for i in range(512)))
        class Failed:
            def ordered(self,function,arguments,stats):
                yield function(next(iter(arguments)))
                raise RuntimeError('worker died')
        bridge.cpu=Failed()
        with self.assertRaisesRegex(RuntimeError,'worker died'):bridge.poll()
        self.assertEqual((self.root/'checkpoint.json').read_bytes(),before)
        recovered=self.m.Bridge(*self.args);recovered.cpu=CPUExecutor(1)
        try:self.assertEqual(recovered.poll(),512)
        finally:recovered.cpu.close()
        self.assertEqual({row['query'] for row in self.rows()}, {'first'}|{str(i)+'x'*1800 for i in range(512)})


if __name__=='__main__':unittest.main()
