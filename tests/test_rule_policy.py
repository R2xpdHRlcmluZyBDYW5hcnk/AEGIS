"""Selector compilation, ordered process chunks and bounded worker budgets."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock
import rule_policy as runtime


class PolicyRuntimeTests(unittest.TestCase):
    def test_spawn_import_does_not_run_the_updater_entrypoint(self):
        import runpy
        with mock.patch('snort_rules.main',side_effect=AssertionError('entrypoint ran during spawn import')) as entry:
            runpy.run_path(str(Path(__file__).resolve().parents[1]/'ips-snort-rules'),run_name='__mp_main__')
        entry.assert_not_called()

    def test_selector_kinds_preserve_identity_source_and_action_precedence(self):
        text=('alert tcp any any -> any any (msg:"First"; sid:1;)\n'
              'alert udp any any -> any any (msg:"DNS"; sid:2; flowbits:noalert;)\n'
              'alert tcp any any -> any any (msg:"Other GID"; gid:129; sid:1;)\n'
              '# alert tcp any any -> any any (msg:"Disabled"; sid:3;)\n')
        groups={'1':{'web'},'2':{'dns'},'129:1':{'web'}}
        result=runtime.apply_policy(text,groups,disabled=['sid:129:1'],dropped=['group-source:example%2Fsource:web'],
                                    rejected=['group:dns'],overrides=[('reject','msg:First*')],source='example/source',workers=1)
        self.assertTrue(result.startswith('reject tcp'))
        self.assertIn('\nalert udp',result,'noalert prevents a group blocking action')
        self.assertIn('\n# alert tcp any any -> any any (msg:"Other GID"',result)
        self.assertTrue(result.endswith('# alert tcp any any -> any any (msg:"Disabled"; sid:3;)\n'))
        wrong_source=runtime.apply_policy(text,groups,dropped=['group-source:other:web'],source='example/source',workers=1)
        self.assertEqual(wrong_source,text)

    def test_missing_message_does_not_match_message_wildcards(self):
        text='alert ip any any -> any any (sid:1;)\n'
        self.assertEqual(runtime.apply_policy(text,{},disabled=['msg:*'],workers=1),text)
        self.assertTrue(runtime.apply_policy(text,{},disabled=['re:sid:1;'],workers=1).startswith('# '))

    def test_serial_and_parallel_outputs_match_including_continuations_and_empty_lines(self):
        line='alert tcp any any -> any any (msg:"'+('padding '*90)+'"; sid:1; rev:1;)\n'
        text=line*14000+'\n# comment\nalert udp any any -> any any (\\\nsid:2;)'
        args=dict(groups={'1':{'web'},'2':{'dns'}},dropped=['group:web'],rejected=['sid:2'])
        serial=runtime.apply_policy(text,workers=1,**args);stats={}
        parallel=runtime.apply_policy(text,workers=4,stats=stats,**args)
        self.assertEqual(parallel,serial)
        self.assertGreater(stats['chunks'],1)
        self.assertGreater(stats['processes'],1)
        self.assertLessEqual(stats['processes'],4)
        stats={};self.assertEqual(runtime.apply_policy(text,stats=stats,**args),serial)
        self.assertEqual(stats['processes'],1,'indexed policies avoid process startup cost')
        stats={};runtime.apply_policy(text,{},rejected=['re:sid:2;'],stats=stats)
        self.assertGreater(stats['processes'],1,'large text scans use the bounded process pool')

    def test_chunks_preserve_order_and_worker_count_respects_affinity(self):
        self.assertEqual([line for chunk in runtime.chunks(['a','b'*30,'c'],8) for line in chunk],['a','b'*30,'c'])
        with mock.patch.object(runtime.os,'sched_getaffinity',return_value={0,1},create=True):
            self.assertEqual(runtime.worker_count(99),2)
        self.assertEqual(runtime.worker_count(0),1)


if __name__=='__main__':unittest.main()
