"""Generate synthetic native-backend compatibility fixtures from the Python reference.

Run before retiring the Python implementation; committed fixtures remain runnable
without that implementation. Inputs use documentation addresses only.
"""
import importlib.machinery
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('aegis_legacy_fixture', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
schema_path = ROOT / 'backend/internal/console/schema.json'
schema = json.loads(schema_path.read_text(encoding='utf-8'))
schema.update(hunt_ci=sorted(m.HUNT_CI_FIELDS), hunt_level_aliases=m.HUNT_LEVEL_ALIASES,
              event_kinds=sorted(set(m.BASE_EVENT_TYPES) | m.APP_EVENT_TYPES))
schema_path.write_text(json.dumps(schema, ensure_ascii=False, separators=(',', ':'))+'\n', encoding='utf-8')
base = dict(timestamp='2026-11-07T00:00:00.123456+00:00', src_ip='192.0.2.1',
            dest_ip='198.51.100.2', src_port=12345, dest_port=443, proto='TCP', flow_id=9007199254740993)
cases = []
for kind, payload in [
    ('alert', {'alert': {'signature': 'Example 告警', 'gid': 1, 'signature_id': 1234, 'rev': 2, 'severity': 2,
                       'metadata': {'mitre_tactic_id': ['ta0001,TA0002', 'invalid'], 'mitre_technique_id': ['T1059.001'],
                                    'mitre_tactic_name': ['Initial Access']}}}),
    ('drop', {'drop': {'reason': 'policy'}}),
    ('dns', {'dns': {'type': 'response', 'rrname': 'example.test', 'rcode': 'NOERROR',
                     'answers': [{'rrname': 'example.test', 'rdata': '192.0.2.3'}]}}),
    ('http', {'app_proto': 'http2', 'http': {'hostname': 'example.test', 'url': '/', 'http_method': 'GET',
                                            'version': 2, 'status': 200, 'length': 0}}),
    ('tls', {'tls': {'sni': 'example.test', 'version': 'TLSv1.3', 'client_alpns': ['h2']}}),
    ('flow', {'app_proto': 'http', 'flow': {'age': 1.5, 'state': 'SF', 'pkts_toserver': 2, 'pkts_toclient': 1,
                                           'bytes_toserver': 123, 'bytes_toclient': 456}}),
    ('anomaly', {'anomaly': {'type': 'decoder', 'event': 'bad'}}),
    ('ssh', {'ssh': {'client': {'software_version': 'OpenSSH'}, 'server': {'proto_version': 2}}}),
    ('quic', {'quic': {'sni': 'example.test', 'version': '1'}}),
    ('fileinfo', {'fileinfo': {'filename': 'test.bin', 'size': 0, 'tx_id': 0}}),
]:
    cases.append((kind, dict(base, event_type=kind, **payload)))
for kind, data in [
    ('conn', {'orig_pkts': 2, 'resp_pkts': 1, 'orig_bytes': 100, 'resp_bytes': 200, 'duration': 1.25, 'conn_state': 'SF'}),
    ('dns', {'trans_id': 0, 'query': 'example.test', 'qtype_name': 'A', 'answers': ['192.0.2.3'], 'TTLs': '300, 20'}),
    ('http', {'trans_depth': 0, 'method': 'GET', 'host': 'example.test', 'uri': '/', 'version': '1.1', 'status_code': 200}),
    ('ssl', {'module_identifier': 'ssl', 'server_name': 'example.test', 'version': 'TLSv1.3'}),
    ('notice', {'gid': 1, 'sid': 1234, 'rev': 1, 'msg': 'fixture', 'action': 'reset'}),
    ('weird', {'gid': 116, 'sid': 1, 'msg': 'fixture', 'source': 'decoder'}),
    ('ftp', {'reply_code': 200, 'command': 'NOOP'}),
    ('ssh', {'direction': 'inbound', 'client.version': 'SSH-2.0'}),
]:
    native = dict(ts=1794009600.123456, uid=9007199254740993, proto='tcp',
                  **{'id.orig_h': '192.0.2.1', 'id.resp_h': '198.51.100.2', 'id.orig_p': 12345, 'id.resp_p': 443}, **data)
    cases.append(('native-'+kind, dict(engine='snort3', epoch='0'*32, data=native,
                  rule_metadata={'category': 'test', 'severity': 2, 'metadata': {'mitre_tactic_id': ['TA0001']}})))
session = dict(session_id='a'*32+':0000000000000001', event='end', src='192.0.2.1', dst='198.51.100.2',
               sport=12345, dport=443, proto='TCP', first_observed=1794009600.123456,
               last_observed=1794009601.123456, ts=1794009601.123456, initial_syn_observed=True,
               state_limit_reached=False, orig_pkts=2, resp_pkts=1, orig_wire_bytes=100, resp_wire_bytes=200,
               client_state=3, server_state=3, appid_service='https')
cases.append(('native-session', dict(engine='snort_session', data=session)))
native_fields = {field: (42 if field in m.HUNT_NUMBER_FIELDS else 'Example Évent '+field)
                 for field in __import__('snort_engine').EVENT_FIELDS.values()}
native_fields['session_id']='d'*32+':0000000000000001'
cases.append(('all-projections', dict(base, event_type='alert', snort_native=native_fields,
             alert=dict(signature='Example Évent', signature_id=1234, severity=1,
                        metadata={'mitre_tactic_id':['TA0001'],'mitre_technique_name':['PowerShell']}))))
output = []
for name, event in cases:
    raw = json.dumps(event, ensure_ascii=False, separators=(',', ':')).encode()
    parsed = m.EventStore._parse(raw)
    assert parsed, name
    record, _ = parsed
    values = m.EventDB.__new__(m.EventDB)._values(record, raw.decode())
    columns = {column[0]: value for column, value in zip(m.EventDB.COLUMNS, values) if column[0] != 'raw'}
    output.append(dict(name=name, raw=raw.decode(), record=record, columns=columns))
destination = ROOT / 'backend/internal/console/testdata'
destination.mkdir(exist_ok=True)
(destination / 'events.json').write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
records = [item['record'] for item in output]
queries = set()
for name, field in m.HUNT_FIELDS.items():
    queries.update((name+':*', 'NOT '+name+':*'))
    for record in records:
        value = record.get(field)
        if value in (None, '', []):
            continue
        if isinstance(value, list): value = value[0]
        query = name+':'+json.dumps(str(value),ensure_ascii=False)
        queries.update((query,'NOT ('+query+')',query+' OR type:dns',query+' AND type:alert'))
queries.update(('proto:tcp','level:critical','sig:Example*','Example','example','type:(http OR tls)',
                'status:[200 TO 499]','status:{200 TO 499}','src:'+json.dumps('192.0.2.0/24'),
                'NOT type:alert AND NOT type:drop','mitre_tactic_id:ta0001','mitre_technique_name:*shell*'))
expected = []
for query in sorted(queries):
    node=m.hunt_parse(query)
    for icase in (False,True):
        expected.append(dict(query=query,icase=icase,total=sum(m.hunt_match(node,r,icase) for r in records)))
(destination/'hunt.json').write_text(json.dumps(expected,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('Reference search cases:',len(expected))
with tempfile.TemporaryDirectory(prefix='aegis-go-reference-') as temporary:
    db=m.EventDB(str(Path(temporary)/'events.db'))
    try:
        for item in output: db.add(item['record'],item['raw'])
        db.flush()
        low,high=1794000000,1794100000
        total,rows=db.search_range(low,high,limit=500)
        count,incident_rows=db.security_incidents(low,high)
        queries=dict(low=low,high=high,search=dict(total=total,events=rows),
                     security=db.security_summary(start=low,end=high,dedup=True),
                     network=__import__('overview_metrics').summarize(db.conn,low,high),
                     incidents=dict(total=count,incidents=incident_rows))
        queries['network'].pop('as_of',None)
        (destination/'queries.json').write_text(json.dumps(queries,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    finally: db.conn.close()
print('Synthetic Python reference cases:', len(output))
print('Reference event fields:', len(schema['columns']), 'hunt aliases:', len(schema['hunt_fields']))
