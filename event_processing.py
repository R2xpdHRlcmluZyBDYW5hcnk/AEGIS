"""Pure batch transformations for bridge, ingestion and historical projections."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys

from snort_engine import record_kind


def decode_bridge(argument):
    lines, epoch, decoder = argument
    output, buffer, rejected, written = [], bytearray(), 0, 0
    for line in lines:
        try:
            data = json.loads(line)
            if not isinstance(data,dict):
                raise ValueError('Native event must be an object')
            if decoder:
                if data.get('gid') != 116:
                    continue
                kind = 'decoder'
            else:
                kind = record_kind(data)
            if not kind:
                raise ValueError('Unknown native event shape')
            envelope = dict(engine='snort3',epoch=epoch,kind=kind,data=data)
            if kind == 'notice':
                # Only these rare records need the privileged rule metadata cache.
                int(data.get('gid') or 0)
                int(data.get('sid') or 0)
                if buffer:
                    output.append(bytes(buffer))
                    buffer.clear()
                output.append(envelope)
            else:
                buffer.extend(json.dumps(envelope,ensure_ascii=False,separators=(',',':')).encode()+b'\n')
            written += 1
        except (ValueError,TypeError,RecursionError,OverflowError):
            rejected += 1
    if buffer:
        output.append(bytes(buffer))
    return output, rejected, written


_backend = None


def backend():
    global _backend
    if _backend is None:
        name = '_ips_cpu_backend'
        loader = importlib.machinery.SourceFileLoader(name,str(Path(__file__).with_name('ips-web')))
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name,loader))
        sys.modules[name] = module
        loader.exec_module(module)
        _backend = module
    return _backend


def parse_events(argument):
    records, prepare = argument
    module = backend()
    db = object.__new__(module.EventDB)
    output = []
    for line, offset in records:
        parsed = module.EventStore._parse(line)
        if not parsed:
            continue
        rec, raw = parsed
        rec['off'] = offset
        values = None
        if prepare:
            try:
                values = db._values(rec,raw.decode('utf-8','replace'))
            except (TypeError,ValueError,KeyError):
                pass
        output.append((rec,None,values))
    return output


def projection_rows(records):
    # Reuse the authoritative tuple representation rather than maintaining a second hash.
    module = backend()
    return [(*row, 'community:'+row[14] if row[14] else
             ('tuple:'+hashed if (hashed:=module.tuple_hash(row[5],row[15],row[6],row[16],row[8])) else None))
            for row in records]


def match_hunt_rows(argument):
    rows, names, keys, need_raw, node, icase = argument
    module=backend();db=object.__new__(module.EventDB);db.names=names
    output=[]
    for row,identity in rows:
        lite=db._row(row,matcher=True,need_raw=True) if need_raw else db._row_lite(row,keys)
        if module.hunt_match(node,lite,icase):
            output.append((row,identity,lite if need_raw else None))
    return output


def history_records(argument):
    lines,cutoff,spec=argument
    module=backend();output=[]
    for line in lines:
        parsed=module.EventStore._parse(line)
        if not parsed:continue
        rec,raw=parsed
        if rec['ts']<cutoff or (spec is not None and not module.hunt_match(spec[0],rec,spec[1])):
            continue
        rec['id']=None;rec['_raw']=raw.decode('utf-8','replace')
        output.append(rec)
    return output


def memory_records(argument):
    records,options,spec=argument
    module=backend();output=[]
    for event,raw in records:
        if raw is not None:
            parsed=module.EventStore._parse(raw.encode('utf-8'))
            if parsed is not None:event=dict(parsed[0],id=event['id'])
        if options['end'] is not None and event['ts']>options['end']:continue
        if event['ts']<options['cutoff']:continue
        if spec is not None and not module.hunt_match(spec[0],event,spec[1]):continue
        if options['type']!='all' and event['type']!=options['type']:continue
        if options['sev'] is not None and event['sev'] not in options['sev']:continue
        if options['proto'] and event['proto'].upper()!=options['proto'].upper():continue
        if options['action'] and event['action']!=options['action']:continue
        if options['q'] and options['q'] not in ' '.join(event[key] for key in ('sig','src','dst','app','reason','cat')).lower():continue
        output.append(event)
    return output
