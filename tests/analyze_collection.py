"""Analyze bounded local native-log copies without displaying identities or addresses."""
import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from snort_engine import record_kind


def analyze(raws):
    bad=0;seen=collections.Counter();kinds=collections.Counter();events=collections.Counter()
    sessions=collections.defaultdict(list);weirds=collections.Counter();conn=collections.Counter();stamps=[]
    for raw in raws:
        for line in raw.splitlines():
            try:
                item=json.loads(line)
                if not isinstance(item,dict):raise ValueError('Expected an object')
                data=item.get('data',item)
                if not isinstance(data,dict):raise ValueError('Expected event data')
                kind='session' if item.get('engine')=='snort_session' else item.get('kind') or record_kind(data)
                if not kind:continue
                stamp=float(data.get('ts') or data.get('last_observed') or 0)
                if not math.isfinite(stamp):raise ValueError('Invalid timestamp')
                if stamp:stamps.append(stamp)
                kinds[kind]+=1;seen[hashlib.sha256(line).digest()]+=1
                identity=data.get('session_id')
                if kind=='session' and identity:
                    sessions[identity].append(data);events[data.get('event')]+=1
                if kind=='conn' and identity:conn[identity]+=1
                if kind=='weird' and identity:
                    key=(identity,data.get('gid'),data.get('sid'),data.get('source'),data.get('msg'))
                    weirds[key]+=1
            except (ValueError,TypeError,KeyError):bad+=1
    redundant=collections.Counter();finals=0;starts=0;after_end=0
    def states(value):return value.get('client_state'),value.get('server_state')
    def apps(value):return tuple(value.get('appid_'+name+'_id') for name in ('service','client','payload','misc','referred'))
    def counters(value):return tuple(value.get(key) for key in ('orig_pkts','resp_pkts','orig_wire_bytes','resp_wire_bytes'))
    for items in sessions.values():
        previous=None;ends=0;begins=0
        for data in sorted(items,key=lambda row:float(row.get('ts',0))):
            event=data.get('event');after_end+=bool(ends);ends+=event=='end';begins+=event in ('start','first_observed')
            if previous:
                if event=='state' and states(data)==states(previous):redundant['same_state']+=1
                if event=='application' and apps(data)==apps(previous):redundant['same_application']+=1
                if event=='update' and (states(data),apps(data),counters(data))==(states(previous),apps(previous),counters(previous)):
                    redundant['unchanged_update']+=1
            previous=data
        finals+=max(0,ends-1);starts+=max(0,begins-1)
    return dict(records=sum(kinds.values()),kinds=dict(kinds),timestamp_span_seconds=round(max(stamps)-min(stamps),3) if stamps else 0,
        exact_duplicates=sum(count-1 for count in seen.values()),session_events=dict(events),sample_sessions=len(sessions),
        max_events_per_session=max(map(len,sessions.values()),default=0),redundant_events=dict(redundant),duplicate_ends=finals,
        duplicate_starts=starts,events_after_end=after_end,repeated_connection_summaries=sum(count-1 for count in conn.values()),
        weird_records=kinds['weird'],weird_records_without_session=kinds['weird']-sum(weirds.values()),weird_session_signatures=len(weirds),max_same_weird_per_session=max(weirds.values(),default=0),
        top_weirds=[dict(gid=key[1],sid=key[2],records=count) for key,count in weirds.most_common(3)],partial_or_invalid_lines=bad)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs',type=Path,nargs='+',help='Native-log copies in the development computer system temp directory')
    args=parser.parse_args();raws=[];remaining=32<<20
    for path in args.inputs:
        path=path.resolve()
        if not path.is_relative_to(Path(tempfile.gettempdir()).resolve()) or path.is_relative_to(ROOT):
            parser.error('Copy source logs to this computer system temporary directory first')
        with path.open('rb') as handle:data=handle.read(remaining)
        raws.append(data);remaining-=len(data)
        if not remaining:break
    print(json.dumps(analyze(raws),indent=2))
    print('Bounded samples can contain partial sessions; timestamp span is not continuous observation coverage.')
