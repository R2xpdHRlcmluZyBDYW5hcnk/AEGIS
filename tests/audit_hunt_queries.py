"""Audit installed query code against real events through a read-only connection.

Print field names and failure categories, never event contents or credentials.
"""
import argparse
import importlib.machinery
import importlib.util
import json
import sqlite3
import urllib.request
import zlib


def load_backend(path):
    loader = importlib.machinery.SourceFileLoader('audit_backend', path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def literal(value):
    value = str(value)
    if '"' not in value:
        return '"' + value + '"'
    if "'" not in value:
        return "'" + value + "'"
    return json.dumps(value, ensure_ascii=False)


def audit(backend, config, progress=None, window_minutes=None):
    path = config.get('event_db') or backend.EVENT_DB
    db = backend.EventDB(':memory:')
    db.conn.close()
    db.conn = sqlite3.connect('file:' + path + '?mode=ro', uri=True,
                              check_same_thread=False, timeout=10)
    db.conn.execute('PRAGMA query_only=ON')
    db.path = path
    app = backend.App.__new__(backend.App)
    app.db = db
    app.store = backend.EventStore(backend.EVE)
    app.store.db = db
    app.store.ingest = lambda: None
    failures, tested, missing, wide_fields = [], set(), [], []
    cases = 0
    try:
        types = [row[0] for row in db.conn.execute('SELECT DISTINCT type FROM events')]
        rows = []
        for event_type in types:
            rows.extend(db.conn.execute('SELECT ' + ','.join(db.names) +
                         ' FROM events WHERE type=? ORDER BY ts DESC LIMIT 50', (event_type,)))
        records = [db._row(row, matcher=True, need_raw=True) for row in rows]
        samples_by_name = {}
        for name, field in backend.HUNT_FIELDS.items():
            samples = []
            seen = set()
            for record in records:
                actual = record.get(field)
                values = actual if isinstance(actual, list) else [actual]
                for value in values:
                    if value is None or value == '':
                        continue
                    marker = str(value)
                    if marker not in seen:
                        samples.append((record, value))
                        seen.add(marker)
                if len(samples) >= 2:
                    break
            if not samples:
                missing.append(name)
                continue
            samples_by_name[name] = samples[0]
            tested.add(name)
            for record, value in samples[:2]:
                plain = literal(value)
                variants = [('compact', name + ':' + plain), ('spaced', name + ': ' + plain),
                            ('exists', name + ': *'),
                            ('combined', name + ': ' + plain + ' AND type: ' + literal(record['type'])),
                            ('or', name + ': ' + plain + ' OR type: ' + literal(record['type'])),
                            ('not', 'NOT NOT (' + name + ': ' + plain + ')')]
                column = db.REC_KEY_COLUMN.get(field, field)
                if column in db.NUMERIC_COLUMNS:
                    variants.append(('numeric', name + ': >=' + str(value)))
                for kind, query in variants:
                    cases += 1
                    try:
                        node = backend.hunt_parse(query)
                        if not backend.hunt_match(node, record, icase=True):
                            failures.append({'field': name, 'case': kind, 'stage': 'matcher'})
                            continue
                        result = app.hunt({'q': query, 'source': 'db', 'icase': '1',
                                           'from': str(record['ts'] - .01),
                                           'to': str(record['ts'] + .01), 'limit': '500'})
                        if result.get('error') or not result.get('total'):
                            failures.append({'field': name, 'case': kind, 'stage': 'query',
                                             'error': result.get('error')})
                        elif result.get('truncated'):
                            failures.append({'field': name, 'case': kind, 'stage': 'truncated'})
                    except Exception as exc:
                        failures.append({'field': name, 'case': kind, 'stage': type(exc).__name__})
        # Wide queries must not depend on the limited Python row-scan path.
        low, high = db.history_range()
        if window_minutes is not None:
            low = max(low,high-window_minutes*60)
        columns = {key: column for column, key in backend.EventDB.COLUMNS}
        columns.update({'dns': 'dnsname', 'file': 'fname', 'size': 'fsize'})
        for index, (name, field) in enumerate(backend.HUNT_FIELDS.items()):
            if progress and index % 10 == 0:
                progress('Checking wide-range fields: ' + name)
            query = name + ': *'
            cases += 1
            db.conn.execute('BEGIN')
            try:
                if field in backend.MITRE_FIELDS:
                    expected = 0
                    for raw, in db.conn.execute('SELECT raw FROM events WHERE ts>=? AND ts<=? AND length(raw)>0',
                                                (low * 1000, high * 1000)):
                        try:
                            expected += bool(backend.attack_metadata(json.loads(zlib.decompress(raw))).get(field))
                        except (ValueError, TypeError, zlib.error):
                            pass
                else:
                    column = columns.get(field)
                    if field == 'httpver':
                        column = "(CASE WHEN type='quic' THEN '' WHEN COALESCE(httpver,'')='' AND (type='http2' OR (type='http' AND app='http2')) THEN 'HTTP/2' ELSE COALESCE(httpver,'') END)"
                    clause = 'sev>=1' if field == 'level' else column + " IS NOT NULL AND " + column + "!=''"
                    expected = db.conn.execute('SELECT COUNT(*) FROM events WHERE ts>=? AND ts<=? AND ' + clause,
                                               (low * 1000, high * 1000)).fetchone()[0]
                result = app.hunt({'q': query, 'from': str(low), 'to': str(high), 'source': 'db', 'limit': '5'})
                if result.get('error') or result['total'] != expected or result.get('truncated'):
                    failures.append({'field': name, 'case': 'wide-exists', 'stage': 'count-mismatch',
                                     'truncated': result.get('truncated')})
                if name in samples_by_name:
                    _, value = samples_by_name[name]
                    query = name + ': ' + literal(value)
                    cases += 1
                    _, _, full = backend.hunt_sql_pushdown(backend.hunt_parse(query))
                    if not full:
                        failures.append({'field': name, 'case': 'wide-value', 'stage': 'scan-fallback'})
                wide_fields.append(name)
            finally:
                db.conn.rollback()
        finite_fields = backend.App.hunt_schema()['fields']
        for field in finite_fields:
            name = field['name']
            if not field.get('values'):
                continue
            if progress:
                progress('Checking finite choices: ' + name)
            key = ("CASE WHEN sev=1 THEN 'high' WHEN sev=2 THEN 'medium' WHEN sev>=3 THEN 'low' ELSE '' END"
                   if name == 'level' else 'LOWER(CAST(' + columns[backend.HUNT_FIELDS[name]] + ' AS TEXT))')
            db.conn.execute('BEGIN')
            try:
                counts = dict(db.conn.execute('SELECT ' + key + ',COUNT(*) FROM events WHERE ts>=? AND ts<=? GROUP BY 1',
                                              [int(low * 1000), int(high * 1000)]))
                if name == 'httpver':
                    counts = {}
                    for kind,application,version,count in db.conn.execute('SELECT type,app,httpver,COUNT(*) FROM events WHERE ts>=? AND ts<=? GROUP BY type,app,httpver', [int(low * 1000),int(high * 1000)]):
                        normalized = backend.http_version(kind,application,version).lower()
                        counts[normalized] = counts.get(normalized,0) + count
                for item in field['values']:
                    value = item['value']
                    cases += 1
                    result = app.hunt({'q': name + ': ' + literal(value), 'from': str(low), 'to': str(high),
                                       'source': 'db', 'limit': '1'})
                    expected = sum(count for actual,count in counts.items() if value.lower() in str(actual or '')) if backend.HUNT_FIELDS[name] in backend.HUNT_SUBSTRING_FIELDS else counts.get(value.lower(), 0)
                    if result.get('error') or result['total'] != expected or result.get('truncated'):
                        failures.append({'field': name, 'case': 'finite-' + value, 'stage': 'count-mismatch'})
            finally:
                db.conn.rollback()
        return {'backend': 'installed' if backend.__file__ == '/usr/local/bin/ips-web' else 'candidate', 'window_minutes':window_minutes,
                'readonly': True, 'cases': cases, 'tested_fields': sorted(tested),
                'wide_fields': sorted(wide_fields), 'fields_without_samples': sorted(missing), 'failures': failures}
    finally:
        db.conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', default='/usr/local/bin/ips-web')
    parser.add_argument('--config', default='/etc/ips-web.conf')
    parser.add_argument('--window-minutes',type=int,help='Limit wide-range statistics; per-field historical samples remain covered')
    args = parser.parse_args()
    backend = load_backend(args.backend)
    config = backend.load_config(args.config)
    host = config.get('bind', '127.0.0.1')
    host = '127.0.0.1' if host == '0.0.0.0' else '::1' if host == '::' else host
    if ':' in host:
        host = '[' + host.strip('[]') + ']'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://%s:%s/healthz' % (host, config.get('port', 9000)), timeout=10) as response:
        assert json.load(response).get('ok')
    if args.window_minutes is not None and args.window_minutes <= 0:
        parser.error('--window-minutes must be positive')
    result = audit(backend, config, progress=lambda text: print(text, flush=True),window_minutes=args.window_minutes)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    raise SystemExit(bool(result['failures']))
