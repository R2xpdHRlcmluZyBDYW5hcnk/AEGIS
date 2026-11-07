"""Loopback-only browser fixture. Never install on the router."""
import importlib.machinery
import importlib.util
import json
import os
import time
import signal
import socket
import sys
import tempfile
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
loader = importlib.machinery.SourceFileLoader('ndr_preview', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
temp = tempfile.TemporaryDirectory()
directory = Path(temp.name)
# All mutable paths are isolated before any browser mutation tests run.
for constant, filename in {
    'DISABLE_CONF': 'disable.conf', 'DROP_CONF': 'drop.conf', 'MODIFY_CONF': 'modify.conf',
    'ACTION_CONF': 'action.conf', 'THRESHOLD_CONF': 'threshold.config', 'SUPPRESS_LUA':'suppress.lua',
    'HUNT_RULES': 'hunting.rules', 'LOCAL_RULES': 'local.rules',
    'BAN_RULES': 'bans.rules', 'BAN_STORE': 'bans.json', 'BAN_DETECTOR':'bans.lua',
    'RULE_SCHEDULE': 'schedule.json',
    'UPDATE_CONF': 'rule-update.conf',
}.items():
    target = directory / filename
    target.write_text('[]' if filename.endswith('.json') else '', encoding='utf-8')
    setattr(m, constant, str(target))
m.RULES_FILE = str(directory / 'snort.rules')
Path(m.RULES_FILE).write_text(''.join(
    '%s tcp any any -> any any (msg:"ET SCAN Test signature %03d"; classtype:attempted-recon; sid:%d; rev:1;)\n' % ('rejectboth' if i == 124 else 'alert', i, 2100498 + i)
    for i in range(321 if os.environ.get('NDR_PREVIEW_GROUP_REMOVE') == '1' else 125)), encoding='utf-8')
m.UPDATE_CACHE_DIR = str(directory / 'cache')
Path(m.UPDATE_CACHE_DIR).mkdir()
for name in ('emerging-scan', 'emerging-trojan'):
    (Path(m.UPDATE_CACHE_DIR) / ('fixture-' + name + '.rules')).write_text(
        Path(m.RULES_FILE).read_text().replace('rejectboth ', 'alert ') if name == 'emerging-scan' else '', encoding='utf-8')
m._source_cache_metadata = lambda: {'fixture': ('et/open', True), 'old': ('old/vendor', False)}
if os.environ.get('NDR_PREVIEW_SOURCE_GROUPS') == '1':
    for source,count in (('light',2),('registered',3)):
        (Path(m.UPDATE_CACHE_DIR)/(source+'-browser-chrome.rules')).write_text(''.join(Path(m.RULES_FILE).read_text().splitlines(keepends=True)[:count]),encoding='utf-8')
    m._source_cache_metadata=lambda:{'fixture':('et/open',True),'old':('old/vendor',False),'light':('snort/lightspd',True),'registered':('snort/registered',True)}
m.SOURCES_DIR = str(directory / 'sources')
Path(m.SOURCES_DIR).mkdir()
if os.environ.get('NDR_PREVIEW_SOURCE_FILTER')=='1':
    stopped='alert ip any any -> any any (msg:"Disabled source unique"; sid:9000801; rev:1;)\n'
    (Path(m.UPDATE_CACHE_DIR)/'old-stopped.rules').write_text(stopped+Path(m.RULES_FILE).read_text().splitlines()[0]+'\n')
    with Path(m.RULES_FILE).open('a') as handle:handle.write(stopped)
    Path(m.HUNT_RULES).write_text('alert ip any any -> any any (msg:"Independent manual"; sid:9900802; rev:1;)\n')
if os.environ.get('NDR_PREVIEW_GROUP_REMOVE') == '1':
    (Path(m.UPDATE_CACHE_DIR) / 'fixture-overlap.rules').write_text(''.join(Path(m.RULES_FILE).read_text().splitlines(keepends=True)[:50]),encoding='utf-8')
    (Path(m.UPDATE_CACHE_DIR) / 'old-stopped.rules').write_text('alert ip any any -> any any (msg:"Old source fixture"; sid:9900300; rev:1;)\n',encoding='utf-8')
    pending = lambda sid: m._PENDING_SUPPRESS + m.base64.urlsafe_b64encode(('suppress gen_id 1, sig_id %d'%sid).encode()).decode()+'\n'
    Path(m.THRESHOLD_CONF).write_text('# keep\n'+''.join('suppress gen_id 1, sig_id %d\n'%(2100498+i) for i in range(321))+pending(9900300)+pending(9999999),encoding='utf-8')
if os.environ.get('NDR_PREVIEW_NAVIGATION') == '1':
    Path(m.HUNT_RULES).write_text('alert tcp any any -> any any (msg:"Custom boundary fixture"; sid:9900200; rev:1;)\n',encoding='utf-8')
    Path(m.LOCAL_RULES).write_text('drop udp any any -> any any (sid:9900201; rev:1;)\n',encoding='utf-8')
    Path(m.ACTION_CONF).write_text('reject sid:9900200\ndrop msg:Custom*\n',encoding='utf-8')
    Path(m.DROP_CONF).write_text(m._selector_config_line('group:emerging-*')+'\n'+m._selector_config_line('re:sid:990020')+'\n',encoding='utf-8')
    Path(m.THRESHOLD_CONF).write_text('suppress gen_id 1, sig_id 9900200\n'+m._PENDING_SUPPRESS+'c3VwcHJlc3MgZ2VuX2lkIDEsIHNpZ19pZCA5OTk5OTk5\n',encoding='utf-8')
    bans=[dict(type='ip',value='192.0.2.99'),dict(type='domain',value='example.org',ips=['198.51.100.4'])]
    Path(m.BAN_STORE).write_text(json.dumps(bans),encoding='utf-8')
    Path(m.BAN_RULES).write_text(m.RuleBook._render_rules(bans),encoding='utf-8')
real_run = m.SysInfo.run
def preview_run(command, timeout=8):
    return real_run(command, timeout=timeout)
m.SysInfo.run = staticmethod(preview_run)
static = Path(os.environ.get('NDR_PREVIEW_STATIC_DIR') or ROOT)
if not (static / 'index.html').is_file():
    raise SystemExit('Run python -B preview.py to build a temporary preview')
cfg = dict(m.DEFAULT_CONFIG, static_dir=str(static), password_pbkdf2=m.make_password_hash('preview-only'), bind='127.0.0.1')
app = m.App.__new__(m.App)
app.config, app.started = cfg, m.now()
from llm_assistant import LocalAssistant
app.assistant = LocalAssistant({'enabled':False})
ai_provider = None
if os.environ.get('NDR_PREVIEW_AI') == '1':
    import http.client
    from test_llm_assistant import Provider, model_stage
    ai_provider = ThreadingHTTPServer(('127.0.0.1',0),Provider)
    ai_provider.daemon_threads = True
    ai_provider.entered, ai_provider.cancelled, ai_provider.stop = threading.Event(), threading.Event(), threading.Event()
    ai_provider.stall, ai_provider.finish, ai_provider.text = False, 'stop', None
    ai_provider.calls, ai_provider.cancellations = 0, 0
    threading.Thread(target=ai_provider.serve_forever,daemon=True).start()
    app.assistant = LocalAssistant()
    app.assistant.connection = lambda:http.client.HTTPConnection('127.0.0.1',ai_provider.server_port,timeout=2)
local_copy = os.environ.get('NDR_PREVIEW_DATABASE')
if local_copy:
    local_copy = Path(local_copy).resolve()
    if not local_copy.is_relative_to(Path(tempfile.gettempdir()).resolve()) or local_copy.is_relative_to(ROOT):
        raise SystemExit('Real data preview requires a disposable copy in this computer\'s system temporary directory')
app.db = m.EventDB(str(local_copy or directory / 'events.db'))
app.cache_budget = m.SharedCache.budget(cfg)
app.cache = m.SharedCache(app.cache_budget*3//4)
app.store = m.EventStore(str(directory / 'eve.json'),memory_budget=app.cache_budget//4)
app.store.db = app.db
m.EVE = app.store.path
app.sys, app.rules = m.SysInfo(), m.RuleBook()
Path(m.RULE_SCHEDULE).unlink()
app.rule_schedule = m.RuleUpdateSchedule(app.sys)
app.sources_catalog = lambda: {'sources': [{'name': 'et/open', 'vendor': 'ET', 'summary': 'Test fixture', 'license': 'MIT', 'enabled': True}], 'error': ''}
app.sys.reload_rules = lambda: {'ok': True, 'output': 'Test fixture reload'}
app.sys.sc = lambda *args, **kwargs: {}
app.sys.engine.call = lambda *args, **kwargs: {}
app.sessions, app.auth_lock, app.login_failures = m.Sessions(3600), threading.Lock(), {}
app.sys.service = lambda: dict(state='active', sub='running', pid=1234, uptime=3600, memory=256 * 1024 * 1024)
app.sys.counters = lambda: dict(ips=dict(accepted=1234567, blocked=420, drop_reason=dict(rules=400)),
    inspection=dict(decoder_discards=19,tcp_gaps=7,tcp_invalid_ack=23,tcp_max_bytes=0,tcp_max_segs=0,event_limit=2))
app.sys.ruleset = lambda: dict(rules_loaded=65000, rules_failed=0, rules_skipped=10)
app.sys.queue = lambda: dict(packets=1234567, queue_total=3, kernel_drops=5, user_drops=7, queues=[], count=4)
app.sys.latest_rates = dict(pps=1240, mbps=8.4, fps=23)
# Exercise the same persistent staging boundary as the DynamicUser deployment.
import ips_control
manager_loader = importlib.machinery.SourceFileLoader('preview_manager_live', str(ROOT / 'ips-web'))
manager_spec = importlib.util.spec_from_loader(manager_loader.name, manager_loader)
live = importlib.util.module_from_spec(manager_spec)
manager_loader.exec_module(live)
from rule_drafts import CONTROLS
for name in (*CONTROLS, 'RULES_FILE', 'RULE_SCHEDULE', 'SOURCES_DIR', 'UPDATE_CACHE_DIR', 'UPDATE_CONF'):
    setattr(live, name, getattr(m, name))
live.SNORT_CONF = str(directory / 'snort.lua')
live.DIST_RULES_DIR = str(directory / 'dist')
live.SysInfo.run = staticmethod(preview_run)
manager = ips_control.Manager(live, str(directory / 'manager-state'))
manager.drafts.module._source_cache_metadata = m._source_cache_metadata
manager.jobs.run = lambda *a, **kw: None
manager.jobs.local.engine.call = lambda commands, **kw: {name:{} for name in commands}
manager.jobs.local.ruleset = app.sys.ruleset
manager.jobs.local.service = app.sys.service
if os.environ.get('NDR_PREVIEW_COMPONENT_HEALTH') == '1':
    del app.sys.queue
    manager.jobs.local._queue_listeners=lambda:dict(listeners_known=True,listeners_at=m.now(),
        queues=[dict(id=i,backlog=0) for i in range(4)],count=4,queue_total=0,kernel_drops=0)
manager.runtime.engine={'ruleset-stats':app.sys.ruleset(),'dump-counters':app.sys.counters(),
    'version':'preview','uptime':None,'ruleset-reload-time':None,'running-mode':'inline','capture-mode':'NFQ'}
manager.runtime.as_of=time.time();manager.runtime.error=''
manager.app.sources_catalog = app.sources_catalog
manager.reads['app.sources_catalog'] = manager.app.sources_catalog
if os.environ.get('NDR_PREVIEW_NATIVE_RULES') == '1':
    from native_rules import parse_builtin
    builtin=lambda config:parse_builtin('129:15 (stream_tcp) reset outside window\n129:18 (stream_tcp) data after reset\n119:261 (http_inspect) truncated body\n')
    for module in (live,manager.drafts.module): module.builtin_catalog=builtin
    del manager.app.sources_catalog
    manager.reads['app.sources_catalog']=manager.app.sources_catalog
del app.sources_catalog
class InProcessClient:
    def request(self, operation, **parameters):
        if operation=='history-reset':
            return dict(ok=app.clear_history(),stats=app.db.stats())
        return manager.dispatch(json.loads(json.dumps(dict(operation=operation, **parameters))))
app.control = InProcessClient()
class InProcessRuntime:
    def read(self):
        value=manager.runtime.payload();value['service']=manager.jobs.local.service()
        return value
    def engine_call(self,commands,timeout=10):return manager.runtime.engine_reply(commands)
reload_release=threading.Event();runtime_stop=threading.Event();runtime_threads=[]
runtime_reader=InProcessRuntime()
if os.environ.get('NDR_PREVIEW_BLOCK_RELOAD')=='1':
    engine_values=dict(manager.runtime.engine)
    def synthetic_engine(commands,timeout=10):
        if commands==['ruleset-reload-rules']:
            if not reload_release.wait(30):raise RuntimeError('Synthetic reload was not released')
            return {'ruleset-reload-rules':{'confirmed':True}}
        return {name:engine_values[name] for name in commands}
    manager.jobs.local.engine.call=synthetic_engine
    manager.module.nft_query_table=lambda *args:{}
    runtime_path=directory/'status.json'
    runtime_threads=manager.runtime.start(runtime_stop,runtime_path)
    from runtime_status import RuntimeReader
    runtime_reader=RuntimeReader(runtime_path)
ips_control.install_proxies(m, app.control,runtime_reader)
app.rule_schedule = ips_control.RemoteSchedule(app.control)
job_log_lines = max(0,min(10000,int(os.environ.get('NDR_PREVIEW_JOB_LOG_LINES','0'))))
if job_log_lines:
    for index,(kind,trigger,label) in enumerate((('apply','manual','manual'),('update','scheduled','scheduled')),1):
        identity=format(index,'032x')
        job=dict(id=identity,log_ref=identity,kind=kind,trigger=trigger,state='done',started=m.now()-120+index,
                 finished=m.now()-60+index,rc=0,
                 lines=ips_control.OperationLogLines(manager.jobs.history.log_path(identity)))
        job['lines'].extend([label+' first line',*(label+' line %05d 完整输出'%row for row in range(job_log_lines)),label+' last line'])
        manager.jobs.rule_job=job;manager.jobs.history.checkpoint(job)
        if trigger=='scheduled':manager.app.rule_schedule.finished(job)
events = []
for i, etype in enumerate(('alert', 'alert', 'alert', 'drop', 'dns', 'tls')):
    events.append(dict(timestamp=m.iso(m.now() - i * 30), event_type=etype,
        flow_id=1001, community_id='1:preview', src_ip='192.0.2.10', src_port=51000,
        dest_ip='198.51.100.4', dest_port=443, proto='TCP', app_proto='tls',
        alert=dict(signature='测试数据 Suspicious TLS activity', signature_id=2100000+i,
                   severity=(i % 3)+1, action='blocked' if etype == 'drop' else 'allowed', category='Test fixture'),
        dns=dict(rrname='example.org', rrtype='A'), tls=dict(sni='example.org', version='TLS 1.3')))
for index, app_proto in enumerate(('tls', 'http')):
    end = m.now()-20-index
    events.append(dict(timestamp=m.iso(end),event_type='flow',flow_id=1001+index,community_id='1:preview' if not index else '1:preview-other',
        src_ip='192.0.2.'+str(10+index),src_port=51000+index,dest_ip='198.51.100.4',dest_port=443 if not index else 80,proto='TCP',app_proto=app_proto,
        flow=dict(start=m.iso(end-80),end=m.iso(end),age=80,state='closed',reason='timeout',bytes_toserver=32768,bytes_toclient=16384 if not index else 0,pkts_toserver=20,pkts_toclient=10 if not index else 0)))
if os.environ.get('NDR_PREVIEW_AI')=='1':
    events.append(dict(timestamp=m.iso(m.now()-40),event_type='tls',flow_id=9099,
        src_ip='192.0.2.90',src_port=51990,dest_ip='198.51.100.90',dest_port=443,proto='TCP',
        app_proto='tls',tls=dict(sni='unalerted.example.test',version='TLS 1.3')))
    events.append(dict(timestamp=m.iso(m.now()-170),event_type='dns',flow_id=9100,
        src_ip='192.0.2.10',src_port=51991,dest_ip='198.51.100.53',dest_port=53,proto='UDP',
        app_proto='dns',dns=dict(rrname='example.org',rrtype='A',answers=[dict(rdata='198.51.100.4')])))
for etype in ('alert', 'drop'):
    events.append(dict(timestamp=m.iso(m.now() - 5), event_type=etype,
        flow_id=2002, tx_id=4, community_id='1:preview-pair', src_ip='192.0.2.20', src_port=51020,
        dest_ip='198.51.100.20', dest_port=80, proto='TCP', app_proto='http',
        alert=dict(signature='GPL ATTACK_RESPONSE id check returned root', signature_id=2100498,
                   severity=0 if etype == 'drop' else 2,
                   action='blocked', category='Test fixture')))
if os.environ.get('NDR_PREVIEW_SNORT') == '1':
    events.append(dict(engine='snort3',epoch='preview',data=dict(
        ts=m.now()-1,uid=18446744073709551615,
        **{'id.orig_h':'192.0.2.30','id.orig_p':51030,'id.resp_h':'198.51.100.30','id.resp_p':443},
        module_identifier='ssl',server_name='native.example.test',version='TLS 1.3',
        cipher='TLS_AES_256_GCM_SHA384',curve='secp256r1')))
if os.environ.get('NDR_PREVIEW_SESSION') == '1':
    events.append(dict(engine='snort_session',data=dict(
        session_id='b'*32+':0000000000000001',event='state',ts=m.now()-120,
        first_observed=m.now()-130,last_observed=m.now()-120,
        src='192.0.2.99',sport=45000,dst='198.51.100.99',dport=443,proto='TCP',
        client_state=3,server_state=3,initial_syn_observed=True,state_limit_reached=False,
        orig_pkts=3,resp_pkts=2,orig_wire_bytes=200,resp_wire_bytes=150,
        appid_service='HTTPS',appid_service_id=1122,
        appid_client='fixture <img src=x onerror="window.ndrInjected=true">',appid_client_id=100)))
if os.environ.get('NDR_PREVIEW_REJECT_ONLY')=='1':
    events.append(dict(engine='snort3',kind='notice',epoch='preview',data=dict(
        ts=m.now(),uid=18446744073709551615,session_id='a'*32+':000000000000ffff',
        **{'id.orig_h':'192.0.2.30','id.orig_p':51030,'id.resp_h':'198.51.100.30','id.resp_p':80},
        gid=1,sid=498,rev=1,msg='Native reject only',proto='TCP',action='reset',ips_action='reject')))
if os.environ.get('NDR_PREVIEW_MITRE') == '1':
    events[0]['alert']['metadata'] = dict(mitre_tactic_id=['TA0011'], mitre_tactic_name=['Command_And_Control'],
        mitre_technique_id=['T1568'], mitre_technique_name=['Dynamic_Resolution'])
    events[1]['alert']['metadata'] = dict(mitre_tactic_id=['TA0002'], mitre_technique_id=['T1059.001', 'T1059.001'])
    path = Path(m.RULES_FILE)
    path.write_text(path.read_text().replace('sid:2100498; rev:1;',
        'sid:2100498; rev:1; metadata:mitre_tactic_id TA0002, mitre_technique_id T1059.001;'), encoding='utf-8')
if os.environ.get('NDR_PREVIEW_LONG_FLOW') == '1':
    for index in range(121):
        events.append(dict(timestamp=m.iso(m.now() - 86400 - index), event_type='tls',
            flow_id=1001, community_id='1:preview', src_ip='192.0.2.10', src_port=51000, dest_ip='198.51.100.4',
            dest_port=443, proto='TCP', app_proto='tls', tls=dict(sni='long-flow.example.org')))
if os.environ.get('NDR_PREVIEW_PAGING') == '1':
    for index in range(600):
        events.append(dict(timestamp=m.iso(m.now()-3600-index),event_type='http',flow_id=10000+index,
            src_ip='192.0.2.100',src_port=45000+index,dest_ip='198.51.100.100',dest_port=80,proto='TCP',
            app_proto='http',http=dict(hostname='paging.example.test',url='/fixture/'+str(index),http_method='GET',status=200)))
if os.environ.get('NDR_PREVIEW_PAGING_EVIDENCE') == '1':
    for index in range(60):
        events.append(dict(timestamp=m.iso(m.now()-6000-index),event_type='drop',flow_id=30000+index,
            src_ip='192.0.2.61',src_port=46000+index,dest_ip='198.51.100.61',dest_port=53,proto='UDP',
            alert=dict(signature='Paging fixture',signature_id=9900600,severity=2,action='blocked')))
    for index in range(60):
        events.append(dict(timestamp=m.iso(m.now()-6500-index),event_type='dns',flow_id=30000,
            src_ip='192.0.2.61',src_port=46000,dest_ip='198.51.100.61',dest_port=53,proto='UDP',
            dns=dict(rrname='evidence-'+str(index)+'.example.test',rrtype='A')))
if os.environ.get('NDR_PREVIEW_OVERVIEW') == '1':
    for kind in ('dns','flow'):
        events.append(dict(timestamp=m.iso(m.now()-100),event_type=kind,flow_id=3003,src_ip='192.0.2.53',src_port=45000,
            dest_ip='198.51.100.53',dest_port=53,proto='UDP',app_proto='dns',
            dns=dict(rrname='udp.example.test',type='response'),
            flow=dict(bytes_toserver=120,bytes_toclient=240,pkts_toserver=2,pkts_toclient=2)))
    for index in range(45):
        events.append(dict(timestamp=m.iso(m.now()-300-index),event_type='http',flow_id=3004,
            src_ip='192.0.2.55',src_port=46000,dest_ip='198.51.100.55',dest_port=80,proto='TCP',app_proto='http',
            http=dict(hostname='normal.example.test',url='/fixture/'+str(index),http_method='GET',status=200)))
if os.environ.get('NDR_PREVIEW_NAVIGATION') == '1':
    for event in events:
        if event.get('event_type') == 'drop':event['drop']={'reason':'test "quoted" reason'}
if not local_copy:
    for event in events:
        if event.get('flow_id'):
            event['snort_native']=dict(session_id='a'*32+':'+format(event['flow_id'],'016x'))
    Path(app.store.path).write_text(''.join(json.dumps(event) + '\n' for event in events), encoding='utf-8')
app.store.ingest()
app.db.flush()
app.analytics = m.StoredNetworkStats(app.db)
app.db.analytics = app.analytics
app.network = m.NetworkSnapshots(app.db,cache=app.cache)
if os.environ.get('NDR_PREVIEW_OVERVIEW') == '1':
    app.recent_events = m.RecentEvents(app.db, 16 << 20)
app.data = m.DataService(app,app.cache)
if os.environ.get('NDR_PREVIEW_BLOCK_RELOAD')=='1':
    # Production updates this separately from cached event summaries.
    def sample_overview_runtime():
        while not runtime_stop.is_set():
            app.sample_overview_runtime()
            runtime_stop.wait(2)
    thread=threading.Thread(target=sample_overview_runtime,daemon=True)
    runtime_threads.append(thread);thread.start()
app.analytics.start()
app.data.start()
network_delay = max(0, min(15, float(os.environ.get('NDR_PREVIEW_NETWORK_DELAY', '0'))))
if network_delay:
    network_compute = app.network._compute
    def delayed_network(*args):
        if app.network.stop.wait(network_delay):
            raise RuntimeError('Preview stopped')
        return network_compute(*args)
    app.network._compute = delayed_network
if os.environ.get('NDR_PREVIEW_COMPONENT_HEALTH') == '1':
    def malformed_events(*_args, **_kwargs):
        error = m.sqlite3.DatabaseError('database disk image is malformed')
        error.sqlite_errorcode = m.sqlite3.SQLITE_CORRUPT
        raise error
    app.analytics.summary = lambda *_args, **_kwargs: None
    m.EventDB.compute_network_summary = staticmethod(malformed_events)
app.network.start()
m.Handler.app, m.Handler.config = app, cfg
class PreviewHandler(m.Handler):
    def do_GET(self):
        if self.path=='/__test/ai-status' and ai_provider:
            if not self._require():return
            stages=[model_stage(payload) for payload in getattr(ai_provider,'payloads',[])]
            return self._json(dict(calls=ai_provider.calls,cancellations=ai_provider.cancellations,stages=stages))
        if self.path.startswith('/api/rules') or self.path.split('?', 1)[0] in ('/api/incidents', '/api/events', '/api/hunt'):
            delay = min(5, max(0, float(os.environ.get('NDR_PREVIEW_DELAY', '0'))))
            if delay:
                time.sleep(delay)
        return super().do_GET()

    def do_POST(self):
        if self.path=='/__test/ai-plan' and ai_provider:
            if not self._require():return
            if self.headers.get('X-Requested-With')!='ips-web':return self._error(400,'missing header')
            body=json.loads(self._read_body(1024) or b'{}')
            ai_provider.natural_plan=body.get('mode')=='natural'
            return self._json({'ok':True})
        if self.path=='/__test/ai-stall' and ai_provider:
            if not self._require():return
            if self.headers.get('X-Requested-With')!='ips-web':return self._error(400,'missing header')
            body=json.loads(self._read_body(1024) or b'{}')
            ai_provider.stall=bool(body.get('stall'))
            ai_provider.stream_prefix=bool(body.get('prefix'))
            ai_provider.analysis_prefix=bool(body.get('analysis'))
            ai_provider.reasoning_prefix=bool(body.get('reasoning'))
            if body.get('stage'):ai_provider.stall_stage=body['stage']
            elif hasattr(ai_provider,'stall_stage'):del ai_provider.stall_stage
            return self._json({'ok':True})
        if self.path=='/__test/release-reload' and os.environ.get('NDR_PREVIEW_BLOCK_RELOAD')=='1':
            if not self._require():return
            if self.headers.get('X-Requested-With')!='ips-web':return self._error(400,'missing header')
            reload_release.set();return self._json({'ok':True})
        if self.path == '/__test/reset':
            if not self._require():
                return
            if self.headers.get('X-Requested-With') != 'ips-web':
                return self._error(400, 'missing header')
            for name in ('DISABLE_CONF', 'DROP_CONF', 'MODIFY_CONF', 'ACTION_CONF',
                         'THRESHOLD_CONF', 'HUNT_RULES', 'BAN_RULES', 'BAN_STORE'):
                target = Path(getattr(m, name))
                assert target.parent == directory
                target.write_text('[]' if name == 'BAN_STORE' else '', encoding='utf-8')
            from rule_identity import group_policy_path
            group_policy_path(m.THRESHOLD_CONF).write_text('[]\n')
            manager.drafts.reset()
            return self._json({'ok': True})
        return super().do_POST()

port = int(os.environ.get('NDR_PREVIEW_PORT', '19090'))
server = m.BoundedHTTPServer(('127.0.0.1', port), PreviewHandler)
port = server.server_address[1]
server.daemon_threads = True
signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown,daemon=True).start())
if os.environ.get('NDR_PREVIEW_STOP_FILE'):
    def watch_stop_file():
        while not Path(os.environ['NDR_PREVIEW_STOP_FILE']).exists():
            time.sleep(.25)
        server.shutdown()
    threading.Thread(target=watch_stop_file,daemon=True).start()
print('Preview ready http://127.0.0.1:%d (%s)' % (port,'local disposable data copy' if local_copy else 'synthetic test data'), flush=True)
try:
    server.serve_forever()
finally:
    if ai_provider:
        ai_provider.stop.set();ai_provider.shutdown();ai_provider.server_close()
    reload_release.set();runtime_stop.set()
    for thread in runtime_threads:thread.join(timeout=3)
    deadline=time.monotonic()+3
    while manager.busy and time.monotonic()<deadline:time.sleep(.02)
    server.server_close()
    app.network.close()
    app.data.close()
    app.analytics.close()
    app.db.conn.close()
    temp.cleanup()
