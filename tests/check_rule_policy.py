"""Compare legacy policy output with serial and process-based compiled policies locally."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import snort_rules
import rule_policy


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--key',required=True)
    parser.add_argument('--source',required=True)
    args=parser.parse_args();root=args.snapshot
    spec=importlib.util.spec_from_file_location('legacy_policy',args.baseline)
    legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
    text=(root/'cache/derived'/(args.key+'.rules')).read_text()
    archive=root/'cache'/(args.key+'-rules.tar.gz')
    with tempfile.TemporaryDirectory(prefix='ips-policy-check-') as temporary:
        directory=Path(temporary)
        for name in ('DISABLE_CONF','DROP_CONF','MODIFY_CONF','ACTION_CONF'):
            path=next((root/'pending'/name).iterdir());shutil.copy2(path,directory/path.name)
        groups=legacy.group_members(archive);assert snort_rules.group_members(archive)==groups
        started=time.perf_counter();expected=legacy.apply_policy(text,directory,groups,args.source)
        print(json.dumps(dict(mode='legacy',seconds=time.perf_counter()-started,bytes=len(expected.encode()),sha256=hashlib.sha256(expected.encode()).hexdigest())),flush=True)
        disabled,dropped,rejected=[snort_rules.selectors(directory/name) for name in ('disable.conf','drop.conf','modify.conf')]
        overrides=[tuple(row.split(' ',1)) for row in snort_rules.selectors(directory/'action-override.conf')]
        for workers in (1,4):
            stats={};started=time.perf_counter()
            result=rule_policy.apply_policy(text,groups,disabled,dropped,rejected,overrides,args.source,workers,stats)
            elapsed=time.perf_counter()-started;assert result==expected,'Policy output changed'
            print(json.dumps(dict(mode='compiled',workers=workers,seconds=elapsed,bytes=len(result.encode()),sha256=hashlib.sha256(result.encode()).hexdigest(),**stats)),flush=True)


if __name__=='__main__':main()
