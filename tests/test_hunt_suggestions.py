"""The Angular suggestion catalog must match the query parser, including aliases."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('hunt_coverage_backend', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
backend = importlib.util.module_from_spec(spec)
loader.exec_module(backend)

@unittest.skipUnless((ROOT / 'frontend/node_modules/typescript').is_dir(),
                     'Runs with temporary dependencies during the production frontend build')
class HuntSuggestionCoverage(unittest.TestCase):
    def test_complete_parser_coverage_and_examples(self):
        schema = backend.App.hunt_schema()['fields']
        script = r'''
const fs=require('node:fs'),vm=require('node:vm'),ts=require('./frontend/node_modules/typescript');
const source=fs.readFileSync('frontend/src/app/hunt-fields.ts','utf8');
const output=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
const exported={};vm.runInNewContext(output,{exports:exported});
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',()=>process.stdout.write(JSON.stringify(exported.completeHuntFields(JSON.parse(input)))));
'''
        result = subprocess.run(['node','-e',script], input=json.dumps(schema), cwd=ROOT,
                                text=True, capture_output=True, check=True)
        fields = json.loads(result.stdout)
        names = [field['name'] for field in fields]
        self.assertTrue(set(names) <= set(backend.HUNT_FIELDS))
        self.assertTrue({'uid','history','cipher','fuid','ips_action'} <= set(names))
        self.assertTrue(set(names).isdisjoint({'ja3','ja4','community_id','md5','sha1'}))
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('level', names)
        self.assertNotIn('sev', names)
        for field in fields:
            with self.subTest(field=field['name']):
                self.assertTrue(field['desc'])
                self.assertIsNotNone(backend.hunt_parse(field['example']))
                for item in field.get('values', []):
                    value = json.dumps(item['value'])
                    compact = field['name'] + ':' + value
                    spaced = field['name'] + ': ' + value
                    self.assertEqual(backend.hunt_parse(spaced), backend.hunt_parse(compact))
        self.assertIsNotNone(backend.hunt_parse('level:high'))
        with self.assertRaises(backend.HuntError):
            backend.hunt_parse('sev:1')

    def test_every_candidate_inserts_one_complete_query_value(self):
        fields = backend.App.hunt_schema()['fields']
        script = r'''
const fs=require('node:fs'),vm=require('node:vm'),ts=require('./frontend/node_modules/typescript');
const source=fs.readFileSync('frontend/src/app/hunt-fields.ts','utf8');
const output=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
const exported={};vm.runInNewContext(output,{exports:exported});
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',()=>{
 const fields=JSON.parse(input);process.stdout.write(JSON.stringify(fields.filter(f=>f.values).map(f=>({name:f.name,queries:exported.huntSuggestions(f.name+':',fields).map(s=>s.example)}))));
});
'''
        result = subprocess.run(['node', '-e', script], input=json.dumps(fields), cwd=ROOT,
                                text=True, capture_output=True, check=True)
        offered = {field['name']: field['queries'] for field in json.loads(result.stdout)}
        for name in ('app', 'tlsver', 'type', 'action'):
            self.assertIn(name, offered)
        for field in fields:
            if not field.get('values'):
                continue
            self.assertEqual(len(offered[field['name']]), len(field['values']))
            values = [item['value'].lower() for item in field['values']]
            self.assertEqual(len(values), len(set(values)))
            for item, query in zip(field['values'], offered[field['name']]):
                with self.subTest(field=field['name'], value=item['value']):
                    self.assertEqual(backend.hunt_parse(query), ('cmp', backend.HUNT_FIELDS[field['name']], item['value']))


if __name__ == '__main__':
    unittest.main()
