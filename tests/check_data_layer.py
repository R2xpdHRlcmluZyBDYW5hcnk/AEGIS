"""Run on a developer computer against a disposable database copy, never production."""
import argparse
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import types

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    database = args.database.resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    if not database.is_relative_to(temporary) or database.is_relative_to(ROOT):
        parser.error('Use a disposable copy in this computer\'s system temporary directory')
    loader = importlib.machinery.SourceFileLoader('local_data_check',str(ROOT/'ips-web'))
    spec = importlib.util.spec_from_loader(loader.name,loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    timings = []
    def measure(name,callback):
        started = time.perf_counter()
        value = callback()
        row = dict(name=name,seconds=round(time.perf_counter()-started,6))
        timings.append(row)
        print(json.dumps(row),flush=True)
        return value
    db = measure('open_local_copy',lambda:m.EventDB(str(database)))
    assert db.conn is not None,db.last_error
    stats = m.StoredNetworkStats(db)
    cache = m.SharedCache(96<<20)
    app = m.App.__new__(m.App)
    app.db,app.cache,app.analytics,app.cache_budget = db,cache,stats,128<<20
    app.store = m.EventStore(str(database.parent/'unused-eve.json'),memory_budget=32<<20)
    app.store.db = db
    app.sys = types.SimpleNamespace(**{name:lambda:{} for name in
        ('service','counters','ruleset','queue','current_rates','reload_state','telemetry')})
    app.network = m.NetworkSnapshots(db,cache=cache)
    app.data = m.DataService(app,cache)
    source = sqlite3.connect(database.as_uri()+'?mode=ro',uri=True)
    source.execute('PRAGMA query_only=ON')
    derived = sqlite3.connect(stats.path)
    derived.execute('PRAGMA journal_mode=WAL')
    derived.execute('PRAGMA synchronous=NORMAL')
    stats.install(derived)
    try:
        assert measure('sqlite_quick_check',lambda:source.execute('PRAGMA quick_check').fetchone()[0])=='ok'
        count,oldest,newest = source.execute('SELECT COUNT(*),MIN(ts),MAX(ts) FROM events').fetchone()
        high = newest/1000
        low = high-86400
        params = {'from':str(low),'to':str(high),'limit':'50','offset':'0','view':'list'}
        overview = measure('overview_cold',lambda:app.overview(dict(params,view='panel')))
        assert not overview['security'].get('error'),overview['security']
        measure('overview_cached',lambda:app.overview(dict(params,view='panel')))
        incidents = measure('incidents_cold',lambda:app.incidents(params))
        assert not incidents.get('error'),incidents
        measure('incidents_cached',lambda:app.incidents(params))
        hunt = measure('hunt_list_cold',lambda:app.hunt(params))
        measure('hunt_list_cached',lambda:app.hunt(params))
        assert not any('_raw' in event for event in hunt['events'])
        if hunt['events']:
            detail = measure('record_on_demand',lambda:app.record({'key':hunt['events'][0]['record_id']}))
            assert 'record' in detail
        if incidents['incidents']:
            detail = measure('incident_on_demand',lambda:app.incident(dict(params,id=incidents['incidents'][0]['id'])))
            assert not detail.get('error'),detail
        def backfill():
            initial = True
            while True:
                ready = stats.sync(source,derived,initial)
                initial = False
                if ready:
                    return
        measure('local_projection_backfill',backfill)
        db.analytics = stats
        for label,start,end in [('24h',low,high),('all',oldest/1000,high),('partial',low+13.123,high-59.789)]:
            expected = measure('raw_'+label,lambda:m.EventDB.compute_network_summary(source,start,end))
            actual = measure('projection_'+label,lambda:stats.aggregate(derived,start,end))
            expected.pop('as_of');actual.pop('as_of')
            assert actual==expected,'Projection mismatch: '+label
        app.data.invalidate()
        measure('incidents_with_projection',lambda:app.incidents(params))
        result = dict(database_bytes=database.stat().st_size,rows=count,oldest=oldest/1000,newest=high,
                      list_fields=len(hunt['events'][0]) if hunt['events'] else 0,
                      list_payload_bytes=len(json.dumps(hunt,ensure_ascii=False).encode()),
                      exact_projection=True,cache=app.cache_stats(),timings=timings,
                      scope='Developer computer; temporary real-data copy; no router data processing')
        args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('PASS: real-data copy, lazy evidence, bounded cache and exact statistics',flush=True)
    finally:
        app.data.close();app.network.close();stats.close()
        source.close();derived.close();db.conn.close()


if __name__ == '__main__':
    main()
