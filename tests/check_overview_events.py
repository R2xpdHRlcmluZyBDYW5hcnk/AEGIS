"""Check overview detection counts on an append-only stream copy in local temp.

No production queries, device addresses or event payloads appear in the output.
An excerpt may cover less than the requested window; coverage is reported.
"""
import argparse
from collections import Counter
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stream', type=Path)
    args = parser.parse_args()
    path = args.stream.resolve()
    if not path.is_relative_to(Path(tempfile.gettempdir()).resolve()) or path.is_relative_to(ROOT):
        parser.error('Use a development-machine system temporary copy')
    loader = importlib.machinery.SourceFileLoader('overview_check', str(ROOT/'ips-web'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    first = latest = None
    security = []
    partial = 0
    with path.open('rb') as stream:
        for line in stream:
            parsed = module.EventStore._parse(line)
            if not parsed:
                partial += 1
                continue
            rec = parsed[0]
            first = min(first, rec['ts']) if first is not None else rec['ts']
            latest = max(latest, rec['ts']) if latest is not None else rec['ts']
            if rec['type'] in ('alert', 'drop'):
                security.append(parsed)
    if latest is None:
        parser.error('No parsed events')
    low = latest-15*60
    selected = [p for p in security if low <= p[0]['ts'] <= latest]
    with tempfile.TemporaryDirectory(prefix='ips-overview-check-') as directory:
        db = module.EventDB(str(Path(directory)/'events.db'))
        try:
            for rec, raw in selected:
                db.add(rec, raw.decode('utf-8') if isinstance(raw, bytes) else raw)
            db.flush()
            result = db.security_summary(start=low, end=latest, dedup=True)
            series = db.security_series(15, 1, start=low, end=latest)
            print(json.dumps(dict(
                copied_range=[module.iso(first),module.iso(latest)],
                requested_window=[module.iso(low),module.iso(latest)],
                full_window_covered=first <= low,
                skipped_lines=partial,
                raw_security_types=dict(Counter(p[0]['type'] for p in selected)),
                old_alert_type_count=sum(p[0]['type']=='alert' for p in selected),
                corrected={k:result[k] for k in ('total','alerts','high','drops')},
                trend_totals={k:sum(p[k] for p in series) for k in ('alerts','drops')},
                test_sid_498=[dict(time=module.iso(rec['ts']),type=rec['type'],
                                  severity=rec['sev'],action=rec['action'])
                              for rec,_ in selected if rec.get('sig_id')==498]),indent=2))
        finally:
            db.conn.close()


if __name__ == '__main__':
    main()
