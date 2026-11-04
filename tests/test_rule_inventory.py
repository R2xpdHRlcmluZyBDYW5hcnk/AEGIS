"""Archive discovery and policy edits share parsed text without stale state."""
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from rule_inventory import RuleFiles,parse
from tests import test_group_policies as fixture


class RuleFilesCase(unittest.TestCase):
    def test_parser_preserves_whitespace_escapes_and_long_messages(self):
        message='A'*10000+r' escaped \" quote \\ slash'
        raw=('alert tcp any any -> any any (msg : "'+message+'"; content:"invalidsid:1 invalidgid:2"; gid : 129; sid : 15;)\n'
             '# alert ip any any -> any any (sid:42;)\n'
             'alert ip any any -> any any (content:"sideline";)\n').encode()
        rows=parse(raw)
        self.assertEqual(len(rows),2)
        self.assertEqual((rows[0].token,rows[0].message),((129,15),message))
        self.assertEqual((rows[1].token,rows[1].enabled),(42,False))

    def test_streamed_archive_preserves_member_order_and_skips_other_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extension,mode in (('tar','w'),('tar.gz','w:gz')):
                path=Path(tmp)/('source.'+extension)
                with tarfile.open(path,mode) as archive:
                    for name,raw in [('ignored.bin',b'x'*2000000),('rules/a.rules',b'alert ip any any -> any any (sid:1;)\n'),
                                     ('rules/b.rules',b'# alert ip any any -> any any (sid:2;)\n')]:
                        info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
                groups=RuleFiles().read(path)
                self.assertEqual([name for name,_ in groups],['rules/a.rules','rules/b.rules'])
                self.assertEqual([rows[0].token for _,rows in groups],[1,2])

    def test_archive_cache_reads_once_and_invalidates_after_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source.tar.gz'
            def write(target,sid):
                with tarfile.open(target,'w:gz') as archive:
                    raw=('alert ip any any -> any any (msg:"test"; sid:%d;)\n'%sid).encode()
                    info=tarfile.TarInfo('rules/category.rules');info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
            write(path,1);cache=RuleFiles()
            original=tarfile.open
            with mock.patch('rule_inventory.tarfile.open',wraps=original) as opened:
                first=cache.read(path);self.assertIs(cache.read(path),first);self.assertEqual(opened.call_count,1)
                replacement=Path(tmp)/'replacement.tar.gz';write(replacement,2);replacement.replace(path)
                self.assertEqual(cache.read(path)[0][1][0].sid,2)
                self.assertEqual(opened.call_count,3)  # one writer and two archive reads

    def test_cache_eviction_is_bounded_and_continuations_keep_signature_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache=RuleFiles(limit=400,entries=1)
            for name,sid in (('first',1),('second',2)):
                path=Path(tmp)/(name+'.rules');path.write_text('# alert tcp any any -> any any (msg:"test"; \\\ngid:129; sid:%d;)\n'%sid)
                row=cache.read(path)[0][1][0]
                self.assertEqual(row.token,(129,sid));self.assertFalse(row.enabled)
            self.assertLessEqual(cache.bytes,400);self.assertLessEqual(len(cache.cache),1)


class RulePageCase(unittest.TestCase):
    def setUp(self):
        case=fixture.GroupPoliciesCase();case.setUp();self.addCleanup(case.doCleanups)
        self.manager,self.draft=case.manager,case.draft

    def test_browse_page_skips_unused_governance_and_inventory_categories(self):
        app=self.manager.app
        with mock.patch.object(self.draft,'governance_state',side_effect=AssertionError('unused governance')),\
             mock.patch.object(app.rules,'categories',side_effect=AssertionError('unused categories')):
            result=app.rules_page({'tab':'catalog'})
        self.assertTrue(result['data']['rules']);self.assertEqual(result['governance'],{})
        self.assertNotIn('group_rows',result['data'])

    def test_warm_browse_only_decorates_one_page_and_reuses_visible_order(self):
        module=self.draft;app=self.manager.app
        path=Path(module.UPDATE_CACHE_DIR)/'a-large.rules'
        path.write_text(''.join('alert ip any any -> any any (msg:"Large %d"; sid:%d;)\n'%(sid,sid) for sid in range(1000,3000)))
        first=app.rules_search('',browse=True,include_groups=False)
        with mock.patch.object(module,'signature_key',wraps=module.signature_key) as keys:
            second=app.rules_search('',offset=50,browse=True,include_groups=False)
        self.assertEqual(first['total'],second['total'])
        self.assertLessEqual(keys.call_count,50)
        self.assertFalse({r['selector'] for r in first['rules']}&{r['selector'] for r in second['rules']})
        path.unlink()
        self.assertLess(app.rules_search('',browse=True,include_groups=False)['total'],first['total'])

    def test_group_page_filters_and_slices_before_decorating_members(self):
        module=self.draft
        path=Path(module.UPDATE_CACHE_DIR)/'a-large.rules'
        path.write_text(''.join('alert ip any any -> any any (msg:"Large %d"; sid:%d;)\n'%(sid,sid) for sid in range(1000,3000)))
        module.rule_group_catalog()
        with mock.patch.object(module,'signature_row',wraps=module.signature_row) as decorated:
            page=module.rule_group_detail('large','snort/lightspd',offset=50,limit=10)
        self.assertEqual(page['total'],2000)
        self.assertEqual([r['sid'] for r in page['rules']],list(range(1050,1060)))
        self.assertEqual(decorated.call_count,10)
        filtered=module.rule_group_detail('large','snort/lightspd',query='Large 29',offset=5,limit=2)
        self.assertEqual(filtered['total'],100)
        self.assertEqual([r['sid'] for r in filtered['rules']],[2905,2906])

    def test_policy_edit_reuses_archive_text_but_updates_builtin_state(self):
        self.manager.app.rules_page({'tab':'groups'})
        import rule_inventory
        with mock.patch.object(rule_inventory,'parse',wraps=rule_inventory.parse) as parsed:
            result=self.manager.dispatch(dict(operation='mutate',method='POST',path='/api/rules/disable',body={'values':['sid:129:15']}))
            self.assertTrue(result['ok'])
            row=self.manager.app.rules_search('sid:129:15')['rules'][0]
        self.assertFalse(row['enabled']);self.assertEqual(parsed.call_count,0)

    def test_one_read_pins_catalog_but_next_read_discovers_new_rule_file(self):
        module=self.draft;app=self.manager.app
        with module.catalog_view():
            first=module.rule_group_catalog()
            extra=Path(module.UPDATE_CACHE_DIR)/'a-new.rules';extra.write_text('alert ip any any -> any any (sid:777;)\n')
            self.assertIs(module.rule_group_catalog(),first)
        self.assertTrue(any(r['name']=='new' for r in module.rule_group_catalog()))

    def test_replacement_with_preserved_timestamp_and_size_updates_whole_catalog(self):
        module=self.draft;path=Path(module.UPDATE_CACHE_DIR)/'a-one.rules'
        module.rule_group_catalog();info=path.stat()
        changed=path.read_text().replace('sid:101','sid:901')
        candidate=path.with_suffix('.new');candidate.write_text(changed);os.utime(candidate,ns=(info.st_atime_ns,info.st_mtime_ns));candidate.replace(path)
        module.rule_group_catalog()
        self.assertIn(901,module._GROUP_CACHE['members'][('one','snort/lightspd')])

    def test_community_keeps_one_official_group_and_hidden_source_semantics(self):
        module=self.draft;path=Path(module.UPDATE_CACHE_DIR)/'community-rules.tar.gz'
        with tarfile.open(path,'w:gz') as archive:
            raw=b'alert tcp any any -> any any (msg:"MALWARE-CNC test"; sid:850001;)\nalert tcp any any -> any any (msg:"SERVER-WEBAPP test"; sid:850002;)\n'
            info=tarfile.TarInfo('snort3-community-rules/snort3-community.rules');info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
        with mock.patch.object(module,'_source_cache_metadata',return_value={'community':('snort/community',True)}):
            module._GROUP_CACHE['key']=None
            rows=[r for r in module.rule_group_catalog() if r['source']=='snort/community']
            self.assertEqual([(r['name'],r['total']) for r in rows],[('snort3-community',2)])
