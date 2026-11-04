"""Download pinned MITRE STIX inputs and generate the offline UI catalog."""
import html
import json
from pathlib import Path
import re
import textwrap

from .runtime import download


def generate(frontend, work, sources=None):
    source = json.loads((sources or Path(__file__).with_name('attack-sources.json')).read_text())
    entries = {}
    for bundle in source['bundles']:
        target = work / bundle['url'].rsplit('/', 1)[-1]
        download(bundle['url'], target, bundle['sha256'])
        for obj in json.loads(target.read_bytes())['objects']:
            if obj.get('type') not in ('x-mitre-tactic', 'attack-pattern'):
                continue
            for reference in obj.get('external_references', []):
                code = reference.get('external_id', '')
                if not reference.get('source_name', '').startswith('mitre-') or not re.fullmatch(r'TA\d{4}|T\d{4}(?:\.\d{3})?', code):
                    continue
                if code in entries and entries[code]['modified'] >= obj.get('modified', ''):
                    continue
                description = obj.get('description', '').split('\n\n')[0]
                description = re.sub(r'\(Citation: [^)]*\)', '', description)
                description = re.sub(r'\[([^]]+)\]\([^)]+\)', r'\1', description)
                description = html.unescape(re.sub(r'[*`_]', '', description))
                description = re.sub(r'\s+', ' ', description).strip()
                sentence = re.split(r'(?<=[.!?])\s+', description, maxsplit=1)[0]
                entries[code] = {'modified': obj.get('modified', ''), 'data': [obj['name'], textwrap.shorten(sentence, width=360, placeholder='…'), bool(obj.get('revoked') or obj.get('x_mitre_deprecated'))]}
    catalog = {code: value['data'] for code, value in sorted(entries.items())}
    (frontend / 'src/app/attack-catalog.ts').write_text(
        '// MITRE ATT&CK official STIX snapshot: ' + source['commit'] + '\n'
        '// https://github.com/mitre-attack/attack-stix-data ; https://attack.mitre.org/resources/terms-of-use/\n'
        + 'export const attackCatalog:Record<string,[string,string,boolean]>=' + json.dumps(catalog, ensure_ascii=False, separators=(',', ':')) + ';\n', encoding='utf-8')
    license = source['license']
    download(license['url'], frontend / 'src/mitre-attack.LICENSE.txt', license['sha256'])
