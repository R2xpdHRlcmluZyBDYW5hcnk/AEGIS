"""Read-only text catalog benchmark against a development-machine snapshot.

Snapshot layout: cache/, rules/, pending/ (manager draft), snort.lua.
Never point this tool at production paths or run it on the detection device.
"""
import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import platform
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,default=ROOT)
    args=parser.parse_args()
    root=args.snapshot.resolve();source=args.source_root.resolve()
    if not all((root/name).exists() for name in ('cache','rules','pending','snort.lua')):
        parser.error('Snapshot is missing required local copies')
    sys.path[:0]=[str(source),str(ROOT)]
    loader=importlib.machinery.SourceFileLoader('catalog_benchmark',str(source/'ips-web'))
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(module)
    module.RULES_FILE=str(root/'rules/snort.rules')
    module.UPDATE_CACHE_DIR=str(root/'cache');module.DIST_RULES_DIR=str(root/'absent-dist')
    module.SOURCES_DIR=str(root/'pending/data/update/sources');module.SNORT_CONF=str(root/'snort.lua')
    for name in ('LOCAL_RULES','HUNT_RULES','BAN_RULES','BAN_STORE','BAN_DETECTOR','THRESHOLD_CONF','SUPPRESS_LUA','DISABLE_CONF','DROP_CONF','MODIFY_CONF','ACTION_CONF'):
        setattr(module,name,str(root/'pending'/name/Path(getattr(module,name)).name))
    # Benchmark text inventory only; do not execute the installed detection engine.
    module.builtin_catalog=lambda _:{}
    app=object.__new__(module.App)

    def measured(call):
        start=time.perf_counter();result=call()
        return result,(time.perf_counter()-start)*1000

    browse=lambda:app.rules_search('',browse=True,include_groups=False)
    first,cold=measured(browse)
    warm=[measured(browse)[1] for _ in range(7)]
    index=app.rules_index()
    digest=hashlib.sha256(json.dumps(index['rules'],ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    group=max(module.rule_group_catalog(),key=lambda row:row['total'])
    detail,group_time=measured(lambda:module.rule_group_detail(group['name'],group['source'],limit=50))
    # Hash every parsed member, including duplicate/disabled upstream records.
    from rule_inventory import FILES
    parsed=hashlib.sha256()
    for path in sorted((root/'cache').iterdir()):
        if path.name.endswith(('.tar.gz','.tgz','.tar','.rules')):
            parsed.update(path.name.encode())
            for name,rows in FILES.read(path):
                parsed.update(name.encode())
                for row in rows:parsed.update(json.dumps(row,ensure_ascii=False,separators=(',',':')).encode()+b'\n')
    print(json.dumps(dict(python=platform.python_version(),scope='local text inventory',rules=first['total'],
                         cold_ms=cold,warm_ms=warm,warm_median_ms=statistics.median(warm),
                         group_members=detail['total'],group_page_ms=group_time,
                         catalog_sha256=digest,parsed_sha256=parsed.hexdigest()),indent=2))


if __name__=='__main__':main()
