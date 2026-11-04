"""Read-only selector details cover generated, custom, cached and ban rules."""
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('selection_backend',str(ROOT/'ips-web'))
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec);loader.exec_module(m)


class RuleSelectionCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        base=Path(self.temp.name)
        paths={name:str(base/name) for name in ('RULES_FILE','LOCAL_RULES','HUNT_RULES','BAN_RULES','BAN_STORE')}
        for path in paths.values():Path(path).write_text('')
        patch=mock.patch.multiple(m,**paths);patch.start();self.addCleanup(patch.stop)
        Path(m.RULES_FILE).write_text('alert ip any any -> any any (msg:"Vendor test"; sid:100; rev:1;)\n')
        Path(m.LOCAL_RULES).write_text('drop tcp any any -> any any (sid:200; msg:"Custom test"; rev:1;)\n')
        Path(m.HUNT_RULES).write_text('alert udp any any -> any any (sid:300; rev:1;)\n')
        m._GROUP_CACHE['rule_records']={400:dict(sid=400,msg='Cached disabled',line='alert ip any any -> any any (msg:"Cached disabled"; sid:400; rev:1;)',action='alert',enabled=False)}
        patch=mock.patch.object(m,'rule_group_catalog',return_value=[dict(name='emerging-scan',source='vendor'),dict(name='emerging-test',source='other')]);patch.start();self.addCleanup(patch.stop)
        self.app=object.__new__(m.App)

    def test_custom_rules_with_sid_before_msg_or_without_msg_are_resolved(self):
        for sid in (100,200,300,400):
            with self.subTest(sid=sid):
                result=self.app.rule_selection('sid:'+str(sid))
                self.assertEqual(result['total'],1)
                self.assertEqual(result['rules'][0]['sid'],sid)
                self.assertIn('sid:'+str(sid),result['rules'][0]['line'])
        self.assertEqual(self.app.rule_selection('sid:30')['total'],0)
        self.assertEqual(self.app.rule_selection('sid:200')['rules'][0]['origins'][0]['source'],'本地规则')

    def test_cache_refreshes_when_custom_file_changes(self):
        self.assertEqual(self.app.rules_search('sid:301')['total'],0)
        with open(m.HUNT_RULES,'a') as handle:handle.write('alert ip any any -> any any (sid:301; rev:1;)\n')
        self.assertEqual(self.app.rules_search('sid:301')['total'],1)

    def test_selector_semantics_pagination_and_invalid_regex(self):
        self.assertEqual(self.app.rule_selection('msg:Custom*')['rules'][0]['sid'],200)
        self.assertEqual(self.app.rule_selection('msg:test')['total'],0,'msg selectors match prefixes, not arbitrary substrings')
        self.assertEqual(self.app.rule_selection('msg:Custom?')['total'],0,'message prefixes do not interpret regex or glob metacharacters')
        self.assertEqual(self.app.rule_selection(r're:sid:(100|200);',limit=1,offset=1)['rules'][0]['sid'],200)
        self.assertEqual(self.app.rule_selection('msg:*',query='disabled')['rules'][0]['sid'],400)
        with self.assertRaises(ValueError):self.app.rule_selection('re:(')
        with self.assertRaises(ValueError):self.app.rule_selection('file:/etc/shadow')

    def test_group_wildcards_and_source_filter_reuse_catalog_members(self):
        with mock.patch.dict(m._GROUP_CACHE,{
            'members':{('emerging-scan','vendor'):{100},('emerging-test','other'):{400}},
            'group_records':{('emerging-scan','vendor'):{100:dict(sid=100,msg='Vendor test')},
                             ('emerging-test','other'):{400:dict(sid=400,msg='Cached disabled')}},
            'actions':{100:'alert'}}):
            self.assertEqual(self.app.rule_selection('group:emerging-*')['total'],2)
            result=self.app.rule_selection('group:emerging-*',source='other')
            self.assertEqual(result['rules'][0]['sid'],400)
            self.assertFalse(result['rules'][0]['enabled'])

    def test_ban_details_only_include_the_selected_objects_generated_rules(self):
        entries=[dict(type='ip',value='192.0.2.1'),dict(type='domain',value='example.org',ips=['192.0.2.2'])]
        Path(m.BAN_RULES).write_text(m.RuleBook._render_rules(entries))
        with mock.patch.object(m.RuleBook,'bans',return_value=entries):
            ip=self.app.rule_selection('ban:192.0.2.1')
            domain=self.app.rule_selection('ban:example.org')
            self.assertEqual(ip['total'],1)
            self.assertEqual(domain['total'],4)
            self.assertTrue(any('appids:' in rule['line'] for rule in domain['rules']))
            self.assertFalse({r['sid'] for r in ip['rules']} & {r['sid'] for r in domain['rules']})
            self.assertEqual(self.app.rule_selection('ban:not-configured.test')['total'],0)


if __name__=='__main__':unittest.main()
