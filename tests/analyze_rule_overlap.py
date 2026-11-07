"""Compare local source candidates, including policy-enabled signatures and revisions."""
import argparse
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from rule_inventory import parse


def inventory(raw):
    revisions={};enabled=set()
    for rule in parse(raw):
        identity=rule.gid,rule.sid
        match=re.search(r'\brev\s*:\s*(\d+)',rule.line)
        revisions[identity]=max(revisions.get(identity,0),int(match[1]) if match else 0)
        if rule.enabled:enabled.add(identity)
    return revisions,enabled


def compare(primary,secondary):
    first,active_first=inventory(primary);second,active_second=inventory(secondary)
    return dict(primary_signatures=len(first),secondary_signatures=len(second),
        shared=len(first.keys()&second.keys()),secondary_only=len(second.keys()-first.keys()),
        secondary_newer=sum(revision>first[key] for key,revision in second.items() if key in first),
        primary_default_enabled=len(active_first),secondary_default_enabled=len(active_second),
        secondary_enabled_but_primary_disabled=len(active_second-active_first))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('primary',type=Path);parser.add_argument('secondary',type=Path)
    args=parser.parse_args();raws=[]
    for path in (args.primary,args.secondary):
        path=path.resolve()
        if not path.is_relative_to(Path(tempfile.gettempdir()).resolve()) or path.is_relative_to(ROOT):
            parser.error('Copy source candidates to this computer system temporary directory first')
        with path.open('rb') as handle:raw=handle.read((128<<20)+1)
        if len(raw)>128<<20:parser.error('Source candidate exceeds the analysis budget')
        raws.append(raw)
    print(json.dumps(compare(*raws),indent=2))
