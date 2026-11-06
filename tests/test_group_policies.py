"""Source-qualified selectors and durable suppression membership/ownership."""
import json
from pathlib import Path
from unittest import mock
import unittest
from tests import test_native_rule_management as fixture
from rule_identity import group_selector,parse_group,group_policy_path
import snort_rules


class GroupPoliciesCase(unittest.TestCase):
    # Keep fixtures without inheriting the unrelated source integration cases.
    def setUp(self):
        fixture.NativeRuleManagementCase.setUp(self)
        self.cache=Path(self.live.UPDATE_CACHE_DIR);self.cache.mkdir()
        self.paths=[self.cache/'a-one.rules',self.cache/'b-one.rules']
        for path,ids in zip(self.paths,((101,102),(102,103))):
            path.write_text('\n'.join('alert ip any any -> any any (msg:"%s %d"; sid:%d; rev:1;)'%(path.name,sid,sid) for sid in ids)+'\n')
        for module in (self.live,self.draft):
            patch=mock.patch.object(module,'_source_cache_metadata',return_value={'a':('snort/lightspd',True),'b':('snort/registered',True)})
            patch.start();self.addCleanup(patch.stop)
        Path(self.live.RULES_FILE).write_text('\n'.join('alert ip any any -> any any (sid:%d; rev:1;)'%sid for sid in (101,102,103,104))+'\n')
        self.a=group_selector('one','snort/lightspd');self.b=group_selector('one','snort/registered')

    mutate=fixture.NativeRuleManagementCase.mutate

    def test_source_qualified_picker_details_exclusion_and_batch_delete(self):
        app=self.manager.app
        groups=[r for r in app.rules_search('',browse=True,exclude='action')['group_rows'] if r['name']=='one']
        self.assertEqual({r['selector'] for r in groups},{self.a,self.b})
        for selector,ids in ((self.a,{101,102}),(self.b,{102,103})):
            rows=app.rule_selection(selector)['rules'];self.assertEqual({r['sid'] for r in rows},ids)
            source=parse_group(selector)[0]
            self.assertTrue(all(r['origins']==[dict(source=source,group='one')] for r in rows))
            collection=app.rule_selection('source:'+source,query='1:102',limit=1)
            self.assertEqual(collection['total'],1)
            self.assertEqual(collection['rules'][0]['origins'],[dict(source=source,group='one')])
        self.assertEqual(app.rule_selection('source:snort/lightspd',query='1:103')['total'],0)
        self.assertEqual(app.rule_selection('source:missing')['total'],0)
        self.assertEqual(app.rules_page({'tab':'groups','q':'1:103'})['data']['matching'],[self.b])
        self.mutate('/api/rules/drop',{'values':[self.a]})
        available={r['selector'] for r in app.rules_search('',browse=True,exclude='action')['group_rows']}
        self.assertNotIn(self.a,available);self.assertIn(self.b,available)
        picker=self.manager.dispatch(dict(operation='read',name='rule_groups_search',args=['1:102','action'],kwargs={}))
        self.assertEqual({r['selector'] for r in picker},{self.b})
        self.mutate('/api/rules/reject',{'values':[self.b]})
        self.mutate('/api/rules/batch-delete',{'paths':['/api/rules/drop/'+__import__('urllib.parse',fromlist=['quote']).quote(self.a,safe='')]})
        self.assertEqual({r['value'] for r in self.draft.governance_state()['drop']},{self.b})

    def test_policies_refresh_members_and_removal_preserves_other_owners(self):
        self.mutate('/api/rules/suppress-groups',{'groups':[self.a,self.b]})
        self.mutate('/api/rules/suppress-groups',{'groups':[],'sids':['102']})
        self.assertEqual(set(self.draft.group_suppression_policies()),{self.a,self.b})
        self.assertEqual(self.draft.group_suppression_members(),{101,102,103})
        with self.paths[0].open('a') as handle:handle.write('alert ip any any -> any any (sid:104; rev:1;)\n')
        self.draft.prepare_thresholds()
        self.assertIn('gid = 1, sid = 104',Path(self.draft.SUPPRESS_LUA).read_text())
        self.mutate('/api/rules/suppress-groups/remove',{'groups':[self.a]})
        self.assertEqual(self.draft.group_suppression_members(),{102,103})
        lua=Path(self.draft.SUPPRESS_LUA).read_text()
        self.assertNotIn('sid = 101',lua);self.assertNotIn('sid = 104',lua)
        self.assertEqual(lua.count('sid = 102'),1)
        self.mutate('/api/rules/suppress-groups/remove',{'groups':[self.b]})
        self.assertEqual([r['sid'] for r in self.draft.governance_state()['suppress']],[102])
        self.assertIn('sid = 102',Path(self.draft.SUPPRESS_LUA).read_text())

    def test_group_draft_survives_restart_and_failed_apply_restores_live_policy(self):
        self.mutate('/api/rules/suppress-groups',{'groups':[self.a]})
        from rule_drafts import RuleDrafts
        rebuilt=RuleDrafts(self.live,self.manager.state)
        self.assertEqual(rebuilt.module.group_suppression_policies(),[self.a])
        group_policy_path(self.live.THRESHOLD_CONF).write_text(json.dumps([self.b]))
        with mock.patch.object(self.fixture.jobs,'run',side_effect=RuntimeError('synthetic failure')):
            self.mutate('/api/actions/apply');self.assertEqual(self.fixture.wait()['rc'],1)
        self.assertEqual(self.live.group_suppression_policies(),[self.b])
        self.assertEqual(self.draft.group_suppression_policies(),[self.a])

    def test_selector_roundtrip_and_source_isolation_in_rule_processing(self):
        selector=group_selector('stream:tcp','Snort 内置')
        self.assertEqual(parse_group(selector),('Snort 内置','stream:tcp'))
        line='alert ip any any -> any any (sid:101; rev:1;)'
        self.assertTrue(snort_rules.matches(self.a,line,('one',),source='snort/lightspd'))
        self.assertFalse(snort_rules.matches(self.a,line,('one',),source='snort/registered'))
        for value in ('group:bad\nname','group-source:x:bad%0Aname'):
            with self.assertRaises(ValueError):parse_group(value)

    def test_disabled_source_filters_browse_search_counts_and_keeps_independent_manual_rules(self):
        app=self.manager.app;module=self.draft
        Path(module.HUNT_RULES).write_text('alert ip any any -> any any (msg:"Independent manual"; sid:9900802; rev:1;)\n')
        with mock.patch.object(module,'_source_cache_metadata',return_value={'a':('snort/lightspd',True),'b':('snort/registered',False)}):
            module._GROUP_CACHE['key']=None
            listed=app.rules_search('',browse=True)
            ids={row['sid'] for row in listed['rules']}
            self.assertIn(101,ids);self.assertIn(102,ids);self.assertIn(9900802,ids)
            self.assertNotIn(103,ids)
            self.assertEqual(app.rules_search('sid:103')['total'],0)
            self.assertEqual(app.rules_search('b-one.rules')['total'],0)
            self.assertEqual(app.rules_search('snort/registered')['total'],0)
            self.assertEqual(app.rules_search('Independent manual')['rules'][0]['sid'],9900802)
            self.assertFalse(any(row['source']=='snort/registered' for row in listed['group_rows']))
            self.assertEqual(module.hunt_rules_list()[0]['sid'],9900802)

    def test_archive_builtin_group_counts_use_native_enabled_state(self):
        module=self.draft
        (self.cache/'c-builtins.rules').write_text('alert (gid:129; sid:15; msg:"first";)\nalert (gid:129; sid:18; msg:"second";)\n')
        with mock.patch.object(module,'_source_cache_metadata',return_value={'a':('snort/lightspd',True),'b':('snort/registered',True),'c':('snort/lightspd',True)}):
            module._GROUP_CACHE['key']=None
            row=next(row for row in module.rule_group_catalog() if row['name']=='builtins')
            self.assertEqual(row['compiled'],2)
            self.mutate('/api/rules/disable',{'values':['sid:129:15']})
            row=next(row for row in module.rule_group_catalog() if row['name']=='builtins')
            self.assertEqual(row['compiled'],1)
            self.assertEqual(row['compiled'],sum(item['enabled'] for item in module.rule_group_members('builtins','snort/lightspd')))


if __name__=='__main__':unittest.main()
