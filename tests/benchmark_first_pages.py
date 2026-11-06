"""Compare authenticated first-page latency and polling CPU on synthetic data."""
import argparse
from collections import Counter
import functools
import http.client
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
QUERY = 'window=1440&view=list&limit=50&offset=0'
PAGES = {
    'overview': '/api/overview?window=1440&view=panel',
    'logs': '/api/hunt?' + QUERY + '&icase=1',
    'alerts': '/api/incidents?' + QUERY,
    'drops': '/api/events?' + QUERY + '&type=drop',
}


def load(path):
    loader = importlib.machinery.SourceFileLoader('benchmark_backend', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def seed(module, path, rows, stamp):
    db = module.EventDB(str(path))
    def records():
        for index in range(rows):
            kind = ('alert', 'drop', 'dns', 'tls', 'flow', 'flow', 'flow', 'flow')[index % 8]
            yield (int((stamp - 14400 + index * 14000 / rows) * 1000), kind,
                   1 if index % 8 < 2 else 2, '192.0.2.' + str(index % 127 + 1),
                   '198.51.100.' + str(index % 11 + 1), 'TCP', 'tls', 443,
                   'Fixture ' + str(index % 100), 1000 + index % 100, 1,
                   'blocked' if kind == 'drop' else 'allowed', 2 if index % 8 < 2 else 1,
                   f'fixture-{index}')
    with db.conn:
        db.conn.executemany('''INSERT INTO events
            (ts,type,sev,src,dst,proto,app,dport,sig,sid,gid,action,tier,event_key)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', records())
    db.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    db.conn.close()


def run_trial(module, path, duration):
    module.Handler.log_message = lambda *args: None
    started = time.perf_counter()
    app = module.App.__new__(module.App)
    app.started = module.now()
    app.config = dict(module.DEFAULT_CONFIG, preload_memory_mib=512, read_workers=4)
    app.db = module.EventDB(str(path))
    app.store = module.EventStore(str(path.with_suffix('.json')), memory_budget=128<<20)
    app.store.db = app.db
    module.EVE = app.store.path
    app.sys = types.SimpleNamespace(**{key: lambda: {} for key in (
        'service', 'counters', 'ruleset', 'queue', 'current_rates', 'reload_state', 'telemetry')})
    # Use the real in-memory network reader. Its independent SQL worker and
    # engine sampling are outside this first-page CPU comparison.
    app.cache = module.SharedCache(384 << 20)
    app.network = module.NetworkSnapshots(app.db, cache=app.cache)
    app.sessions = module.Sessions(300)
    app.data = module.DataService(app, app.cache)
    reads = Counter()
    lock = threading.Lock()
    original = app.data.execute

    @functools.wraps(original)
    def counted(*args, **kwargs):
        with lock:
            reads['background' if kwargs.get('background') else 'foreground'] += 1
        return original(*args, **kwargs)
    app.data.execute = counted
    module.Handler.app = app
    module.Handler.config = app.config
    server = module.BoundedHTTPServer(('127.0.0.1', 0), module.Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    app.data.start()
    worker.start()
    cookie = module.SESSION_COOKIE + '=' + app.sessions.create('fixture', '127.0.0.1')

    def get(path, auth=True, status=200, stream=False):
        stamp = time.perf_counter()
        conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=25)
        try:
            conn.request('GET', path, headers={'Cookie':cookie} if auth else {})
            response = conn.getresponse()
            if stream:
                line = response.readline()
                while line and not line.startswith(b'data:'):
                    line = response.readline()
                data = json.loads(line.removeprefix(b'data:'))
            else:
                data = json.loads(response.read())
            assert response.status == status, (response.status, data)
            if auth:
                assert not data.get('error'), data
            return data, (time.perf_counter()-stamp)*1000
        finally:
            conn.close()

    def load_window(with_ingest, expected):
        with lock:
            initial_reads = reads.copy()
        wall, cpu = time.perf_counter(), time.process_time()
        latencies = {name: [] for name in PAGES}
        for tick in range(0, duration, 5):
            time.sleep(max(0, wall+tick-time.perf_counter()))
            if with_ingest:
                for index, kind in enumerate(('alert', 'drop', 'flow', 'tls')):
                    event = dict(timestamp=module.iso(module.now()-.1), event_type=kind,
                                 src_ip='192.0.2.200', dest_ip='198.51.100.200', proto='TCP',
                                 alert=dict(signature='Batch fixture', signature_id=5000+tick+index,
                                            severity=1, action='blocked' if kind=='drop' else 'allowed'))
                    app.db.add(*module.EventStore._parse(json.dumps(event)))
                app.db.flush()
            for name, path in PAGES.items():
                payload, latency = get(path)
                total = payload['security']['total'] if name == 'overview' else payload['total']
                assert total >= expected[name] if with_ingest else total == expected[name], name
                latencies[name].append(latency)
        time.sleep(max(0, wall+duration-time.perf_counter()))
        cpu_seconds = time.process_time()-cpu
        elapsed = time.perf_counter()-wall
        with lock:
            completed = reads - initial_reads
        return dict(warm_ms=latencies, cpu_seconds=cpu_seconds, elapsed_seconds=elapsed,
                    cpu_percent=100*cpu_seconds/elapsed, sql_reads=dict(completed))

    try:
        get('/healthz', auth=False)
        ready = (time.perf_counter()-started)*1000
        get(PAGES['logs'], auth=False, status=401)
        cold = dict(overview=get('/api/stream?topic=overview&window=1440&view=panel', stream=True)[1],
                    logs=get(PAGES['logs'])[1])
        expected = {}
        for name, path in PAGES.items():
            payload, _ = get(path)
            expected[name] = payload['security']['total'] if name=='overview' else payload['total']
        assert expected['logs'] > 50 and expected['overview'] > 0
        if not duration:
            return dict(ready_ms=ready, cold_ms=cold)
        # Allow the initial warmup and per-query TTL to settle before the load.
        time.sleep(3)
        return dict(ready_ms=ready, cold_ms=cold, steady=load_window(False, expected),
                    ingest=load_window(True, expected), cache=app.cache.stats())
    finally:
        server.shutdown()
        worker.join()
        server.server_close()
        app.data.close()
        app.network.close()
        app.db.conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='HEAD')
    parser.add_argument('--rows', type=int, default=180000)
    parser.add_argument('--duration', type=int, default=30)
    args = parser.parse_args()
    if args.rows < 1000 or args.duration < 20:
        parser.error('Use at least 1000 rows and a 20-second read window')
    with tempfile.TemporaryDirectory(prefix='aegis-first-page-bench-') as temporary:
        root = Path(temporary)
        baseline = root/'baseline.py'
        baseline.write_bytes(subprocess.check_output(
            ['git', 'show', f'{args.baseline}:ips-web'], cwd=ROOT))
        engines = {'before': load(baseline), 'after': load(ROOT/'ips-web')}
        template = root/'fixture.db'
        seed(engines['after'], template, args.rows, time.time())
        results = {name: [] for name in engines}
        for round_index, order in enumerate((('before', 'after'), ('after', 'before'), ('before', 'after'))):
            for name in order:
                target = root/f'{round_index}-{name}.db'
                shutil.copyfile(template, target)
                trial = run_trial(engines[name], target, args.duration if round_index == 0 else 0)
                results[name].append(trial)
                print(json.dumps(dict(version=name, trial=round_index+1, rows=args.rows, **trial)), flush=True)
        for name, trials in results.items():
            summary = dict(version=name, ready_ms=statistics.median(t['ready_ms'] for t in trials),
                           cold_ms={page: statistics.median(t['cold_ms'][page] for t in trials)
                                    for page in ('overview', 'logs')})
            for phase in ('steady', 'ingest'):
                trial = trials[0][phase]
                summary[phase] = dict(warm_ms={page: statistics.median(values)
                                               for page, values in trial['warm_ms'].items()},
                                      cpu_percent=trial['cpu_percent'], sql_reads=trial['sql_reads'])
            print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
