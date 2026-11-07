"""Builtin identities, private source edits and transactional rollback."""
import json
from pathlib import Path
import stat
import unittest
from unittest import mock

from tests import test_rule_manager as manager_fixture
from native_rules import parse_builtin
import rule_sources
import snort_rules

BUILTINS = '129:15 (stream_tcp) reset outside window\n129:18 (stream_tcp) data after reset\n119:261 (http_inspect) truncated body\n'


class NativeRuleManagementCase(unittest.TestCase):
    def setUp(self):
        fixture=manager_fixture.ManagerCase();fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture=fixture
        self.manager=fixture.manager
        self.live=fixture.module
        self.draft=self.manager.drafts.module
        Path(self.live.RULES_FILE).write_text('alert ip any any -> any any (msg:"Different GID"; sid:15; rev:1;)\n')
        for module in (self.live,self.draft):
            patch=mock.patch.object(module,'builtin_catalog',return_value=parse_builtin(BUILTINS))
            patch.start();self.addCleanup(patch.stop)

    def mutate(self,path,body=None,method='POST'):
        return self.fixture.mutate(path,body,method)

    def test_builtin_groups_and_search_keep_same_numbered_text_rule_separate(self):
        m=self.draft;app=self.manager.app
        groups=m.rule_group_catalog()
        self.assertTrue(any(r['name']=='snort-builtin-129-stream_tcp' and r['compiled']==2 for r in groups))
        text=app.rules_search('sid:15')['rules'][0]
        native=app.rules_search('sid:129:15')['rules'][0]
        self.assertEqual((text['gid'],native['gid']),(1,129))
        self.assertTrue(native['builtin'])
        for query, identity in (('1:15', '1:15'), ('129:15', '129:15'), ('SID: 129 : 015', '129:15')):
            self.assertEqual([r['signature'] for r in app.rules_search(query)['rules']], [identity])
        self.assertEqual(app.rules_search('2:15')['total'],0)
        self.assertEqual(app.rules_search('129:15',exclude='action')['total'],0)
        self.assertEqual(app.rules_search('129:15',exclude='suppress')['total'],1)
        selected=app.rule_selection('group:snort-builtin-129-stream_tcp')
        self.assertEqual({r['selector'] for r in selected['rules']},{'sid:129:15','sid:129:18'})
        self.assertEqual(app.rule_selection('group:snort-builtin-129-stream_tcp',query='129:15')['total'],1)
        self.assertEqual(app.rule_selection('group:snort-builtin-129-stream_tcp',query='1:15')['total'],0)
        self.assertEqual(app.rules_search('stream_tcp',exclude='action')['total'],0)

    def test_whole_group_suppression_is_a_draft_and_removal_preserves_other_gid(self):
        self.mutate('/api/rules/suppress',{'sids':['15']})
        self.mutate('/api/rules/suppress-groups',{'groups':['snort-builtin-129-stream_tcp']})
        state=self.draft.governance_state();rows=state['suppress']
        self.assertEqual({(r['gid'],r['sid']) for r in rows},{(1,15)})
        self.assertEqual(state['suppress_groups'][0]['source'],'Snort 内置')
        self.assertEqual(state['suppress_groups'][0]['total'],2)
        self.assertFalse(any(r.get('pending') for r in rows))
        self.assertEqual(Path(self.live.THRESHOLD_CONF).read_text(),'')
        self.assertIn('gid = 129, sid = 15',Path(self.draft.SUPPRESS_LUA).read_text())
        group=next(r for r in self.draft.suppression_group_catalog(True) if r['name']=='snort-builtin-129-stream_tcp')
        self.assertEqual(group['removable'],2)
        self.mutate('/api/rules/suppress-groups/remove',{'groups':['snort-builtin-129-stream_tcp']})
        self.assertEqual([(r['gid'],r['sid']) for r in self.draft.governance_state()['suppress']],[(1,15)])

    def test_encoded_batch_deletion_only_removes_explicit_identity(self):
        self.mutate('/api/rules/suppress',{'sids':['15','129:15']})
        self.mutate('/api/rules/batch-delete',{'paths':['/api/rules/suppress/129%3A15']})
        self.assertEqual([(r['gid'],r['sid']) for r in self.draft.governance_state()['suppress']],[(1,15)])

    def test_builtin_disable_group_is_discoverable_and_generates_native_states(self):
        app=self.manager.app
        self.assertEqual(app.rules_search('sid:129:15',exclude='disable')['total'],1)
        self.mutate('/api/rules/disable',{'values':['group:snort-builtin-129-stream_tcp']})
        self.draft.prepare_thresholds()
        output=Path(self.draft.SUPPRESS_LUA).read_text()
        self.assertIn('alert (gid:129; sid:15; enable:no;)',output)
        self.assertIn('alert (gid:129; sid:18; enable:no;)',output)
        self.assertFalse(app.rules_search('sid:129:15')['rules'][0]['enabled'])
        self.mutate('/api/rules/batch-delete',{'paths':['/api/rules/disable/group%3Asnort-builtin-129-stream_tcp']})
        self.draft.prepare_thresholds()
        self.assertNotIn('enable:no',Path(self.draft.SUPPRESS_LUA).read_text())

    def test_manual_update_downloads_pending_sources_without_promoting_or_reloading(self):
        self.mutate('/api/rules/source',{'name':'snort/community','enable':True})
        with mock.patch.object(self.fixture.jobs,'run') as run:
            self.assertTrue(self.mutate('/api/actions/update')['ok']);result=self.fixture.wait()
        self.assertEqual(result['rc'],0)
        self.assertEqual(run.call_count,1)
        command=run.call_args.args[0]
        self.assertIn('--download-only',command);self.assertIn(str(self.manager.drafts.sources),command)
        self.assertNotIn('--offline',command)
        self.assertTrue(self.manager.drafts.dirty)
        self.assertFalse(Path(self.live.SOURCES_DIR).exists())

    def test_source_credentials_never_cross_public_boundary_and_sources_are_independent(self):
        self.mutate('/api/rules/source/config',{'name':'snort/registered','oinkcode':'a'*40,'registered_version':'3.12.4.0'})
        self.mutate('/api/rules/source',{'name':'snort/community','enable':True})
        self.mutate('/api/rules/source',{'name':'snort/registered','enable':True})
        rows=self.manager.app.sources_catalog()['sources']
        self.assertNotIn('a'*40,json.dumps(rows))
        self.assertEqual({r['name'] for r in rows if r['enabled']},{'snort/community','snort/registered'})
        self.assertFalse(Path(self.live.SOURCES_DIR).exists())
        self.assertTrue((self.manager.drafts.sources/'credentials.json').is_file())
        if __import__('os').name!='nt':
            self.assertEqual(stat.S_IMODE((self.manager.drafts.sources/'credentials.json').stat().st_mode),0o600)

    def test_custom_source_lifecycle_preserves_hidden_address_and_token(self):
        self.mutate('/api/rules/source/config',{'name':'custom/company','label':'Company','url':'https://example.test/rules?key=private','format':'rules','token':'private-bearer'})
        self.mutate('/api/rules/source',{'name':'custom/company','enable':True})
        rows=self.manager.app.sources_catalog()['sources']
        self.assertNotIn('private',json.dumps(rows))
        self.mutate('/api/rules/source/config',{'name':'custom/company','label':'Renamed','url':'','token':''})
        definition=rule_sources.definitions(self.manager.drafts.sources)['custom/company']
        self.assertEqual(definition['token'],'private-bearer')
        self.assertTrue(definition['url'].endswith('key=private'))
        self.assertIn('custom/company',snort_rules.enabled_sources(self.manager.drafts.data))
        self.mutate('/api/rules/source/config',{'name':'custom/company','delete':True})
        self.assertFalse(rule_sources.definitions(self.manager.drafts.sources))

    def test_multiple_official_sources_choose_newest_revision_and_custom_conflicts_preserve_active(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            data=Path(temporary);config=data/'settings.conf';config.write_text('')
            outputs={
                'snort/community':'alert ip any any -> any any (msg:"Older"; sid:101; rev:1;)\nalert ip any any -> any any (sid:102; rev:1;)',
                'snort/registered':'alert ip any any -> any any (msg:"Newer"; sid:101; rev:2;)\nalert ip any any -> any any (sid:103; rev:1;)',
            }
            with mock.patch.object(snort_rules,'enabled_sources',return_value=set(outputs)),mock.patch.object(snort_rules,'update_one',side_effect=lambda d,c,s,*args:outputs[s]):
                snort_rules.update(data,config)
            target=data/'rules/snort.rules';before=target.read_bytes()
            self.assertNotIn(b'Older',before);self.assertIn(b'Newer',before)
            self.assertIn(b'sid:102',before);self.assertIn(b'sid:103',before)
            outputs['custom/example']='alert ip any any -> any any (msg:"Conflict"; sid:101; rev:99;)'
            with mock.patch.object(snort_rules,'enabled_sources',return_value=set(outputs)),mock.patch.object(snort_rules,'update_one',side_effect=lambda d,c,s,*args:outputs[s]):
                with self.assertRaisesRegex(ValueError,'冲突签名'):snort_rules.update(data,config)
            self.assertEqual(target.read_bytes(),before)

    def test_registered_default_uses_published_snapshot(self):
        for version in ('auto','','3.13.2.0'):
            result=snort_rules.pulledpork_config('snort/registered',dict(oinkcode='a'*40,registered_version=version),Path('output'),Path('work'))
            self.assertIn('snort_version = 3.13.0.0',result)
        legacy=snort_rules.pulledpork_config('snort/registered',dict(oinkcode='a'*40,registered_version='3.12.4.0'),Path('output'),Path('work'))
        self.assertIn('snort_version = 3.12.0.0',legacy)

    def test_checksum_mismatch_retries_with_fresh_workspace_and_remains_bounded(self):
        import tempfile
        import types
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);config=root/'settings.conf';config.write_text('')
            attempts=[]
            def run(command,stdout,**kwargs):
                private=Path(command[command.index('-c')+1]);attempts.append(private.parent)
                if len(attempts)==1:
                    stdout.write(b'Official rules checksum differs');return types.SimpleNamespace(returncode=1)
                settings=snort_rules.read_settings(private)
                Path(settings['rule_path']).write_text('alert ip any any -> any any (sid:101; rev:1;)\n')
                original=private.parent/'PulledPork-fixture/downloaded_rulesets/community.tar.gz'
                original.parent.mkdir(parents=True)
                snort_rules.write_rules_archive(original,{'community.rules':'alert ip any any -> any any (sid:101; rev:1;)\n'})
                return types.SimpleNamespace(returncode=0)
            with mock.patch.object(snort_rules.subprocess,'run',side_effect=run):
                self.assertIn('sid:101',snort_rules.update_one(root,config,'snort/community',{},False,root/'pulledpork.py'))
            self.assertEqual(len(set(attempts)),2)
            def mismatch(command,stdout,**kwargs):
                stdout.write(b'Official rules checksum differs');return types.SimpleNamespace(returncode=1)
            with mock.patch.object(snort_rules.subprocess,'run',side_effect=mismatch) as execute:
                with self.assertRaisesRegex(RuntimeError,'checksum differs'):
                    snort_rules.update_one(root,config,'snort/community',{},False,root/'pulledpork.py')
            self.assertEqual(execute.call_count,3)

    def test_failed_apply_rolls_back_active_credential_files_and_keeps_pending_changes(self):
        directory=Path(self.live.SOURCES_DIR)
        rule_sources.configure(directory,dict(name='snort/registered',oinkcode='a'*40))
        self.manager.drafts.reset()
        self.mutate('/api/rules/source/config',dict(name='snort/registered',oinkcode='b'*40))
        with mock.patch.object(self.fixture.jobs,'run',side_effect=RuntimeError('synthetic validation failure')):
            self.mutate('/api/actions/apply');result=self.fixture.wait()
        self.assertEqual(result['rc'],1)
        self.assertEqual(rule_sources.official_credentials(directory)['oinkcode'],'a'*40)
        self.assertEqual(rule_sources.official_credentials(self.manager.drafts.sources)['oinkcode'],'b'*40)
        self.assertTrue(self.manager.drafts.dirty)

    def test_invalid_sources_are_rejected_without_side_effects(self):
        before=self.manager.drafts.signature()
        for body in (dict(name='custom/../../escape',url='https://example.test'),
                     dict(name='custom/x',url='http://example.test'),
                     dict(name='custom/x',url='https://user:password@example.test'),
                     dict(name='snort/registered',oinkcode='bad')):
            with self.assertRaises(ValueError): self.mutate('/api/rules/source/config',body)
        self.assertEqual(self.manager.drafts.signature(),before)

    def test_directory_files_and_groups_are_rediscovered_after_add_edit_and_remove(self):
        root=Path(self.live.RULES_FILE).parent
        directory=root/'vendor';directory.mkdir()
        path=directory/'example.rules'
        path.write_text('alert ip any any -> any any (msg:"Discovered"; sid:9000701; rev:1;)\n')
        app=self.manager.app
        found=app.rules_search('sid:9000701')['rules'][0]
        self.assertFalse(found['enabled'])
        self.assertTrue(any(r['name']=='local/vendor/example' for r in self.draft.rule_group_catalog()))
        path.write_text('alert ip any any -> any any (msg:"Changed"; sid:9000702; rev:1;)\n')
        self.assertEqual(app.rules_search('sid:9000701')['total'],0)
        self.assertEqual(app.rules_search('sid:9000702')['rules'][0]['msg'],'Changed')
        path.unlink()
        self.assertEqual(app.rules_search('sid:9000702')['total'],0)


if __name__=='__main__': unittest.main()
