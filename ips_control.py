"""Local, bounded rule-manager protocol. No caller-supplied commands or paths."""
import inspect
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from snort_engine import configuration_lock
from rule_identity import group_policy_path
from runtime_status import RuntimeSnapshot,RuntimeReader,ENGINE_READS
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from collections import deque

SOCKET = '/run/ips-rule-manager/control.sock'
REQUEST_LIMIT = 256 * 1024
RESPONSE_LIMIT = 16 * 1024 * 1024
FUNCTIONS = ('governance_state', 'rule_group_catalog', 'suppression_group_catalog', 'rule_groups_search',
             'rule_group_detail', 'hunt_rules_list')
APP_READS = ('rules_search', 'sources_catalog', 'rules_payload', 'rule_selection','rules_page')
SYS_READS = ('reload_state','update_status','service')
POST_PATHS = frozenset(('/api/actions/reload', '/api/actions/update', '/api/actions/apply',
    '/api/rules/schedule', '/api/hunt/rules', '/api/hunt/rules/add-apply', '/api/rules/suppress-groups', '/api/rules/suppress-groups/remove',
    '/api/rules/suppress', '/api/rules/action', '/api/rules/source', '/api/rules/source/config',
    '/api/rules/action-apply', '/api/rules/reject', '/api/rules/drop',
    '/api/rules/disable', '/api/rules/batch-delete', '/api/rules/pending/discard', '/api/bans/batch-delete', '/api/bans'))
DELETE_PREFIXES = ('/api/hunt/rules/', '/api/rules/suppress/', '/api/rules/action/',
                   '/api/rules/reject/', '/api/rules/drop/', '/api/rules/disable/', '/api/rules/suppress-group/', '/api/bans/')


def valid_mutation(method, path):
    return isinstance(path, str) and (
        method == 'POST' and path in POST_PATHS or
        method == 'DELETE' and any(path.startswith(p) and len(path) > len(p)
                                   and '/' not in path[len(p):] for p in DELETE_PREFIXES))


def receive(stream, limit):
    raw = stream.readline(limit + 1)
    if len(raw) > limit or not raw.endswith(b'\n'):
        raise ValueError('invalid or oversized message')
    return json.loads(raw)


class Client:
    def __init__(self, path=SOCKET,timeout=70):
        self.path,self.timeout = path,timeout

    def request(self, operation, **parameters):
        raw = json.dumps(dict(operation=operation, **parameters), ensure_ascii=False).encode() + b'\n'
        if len(raw) > REQUEST_LIMIT:
            raise ValueError('request too large')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(self.path)
            connection.sendall(raw)
            with connection.makefile('rb') as stream:
                result = receive(stream, RESPONSE_LIMIT)
        if not result.get('ok'):
            raise RuntimeError(result.get('error', 'rule manager unavailable'))
        return result['result']


class RemoteSchedule:
    def __init__(self, client):
        self.client = client

    def status(self):
        return self.client.request('schedule')


def install_proxies(module, client, runtime=None):
    """Only used in the Web process; helper CLI and manager retain local implementations."""
    if getattr(module, '_control_proxies', False):
        return
    module._control_proxies = True

    def remote(name):
        def call(*args, **kwargs):
            return client.request('read', name=name, args=args, kwargs=kwargs)
        return call

    for name in FUNCTIONS:
        setattr(module, name, remote(name))
    for name in APP_READS:
        function = remote('app.' + name)
        setattr(module.App, name, lambda self, *a, _fn=function, **kw: _fn(*a, **kw))
    if runtime is None:
        runtime=RuntimeReader(Path(client.path).with_name('status.json'))
    for name in SYS_READS:
        def function(_name=name):
            return runtime.read().get(_name,{'state':'unknown'} if _name=='service' else {})
        setattr(module.SysInfo, name, lambda self, _fn=function: _fn())
    module.SysInfo.telemetry=lambda self:runtime.read().get('telemetry',{})
    module.SysInfo._queue_listeners=staticmethod(lambda:runtime.read().get('queue_listeners'))
    module.SysInfo.history_reset_status=lambda self:runtime.read().get('history_reset',{'state':'idle'})
    module.Snort.call = lambda self, commands, timeout=10: runtime.engine_call(commands,timeout)
    module.nft_query_table = lambda family, table: runtime.read().get('queue_table') if (family, table) == ('inet', 'ips') else None


class RuleBackup:
    """Rollback files only; never execute a test engine against an unvalidated candidate."""
    def __init__(self, module, directory):
        import openappid_update
        self.appid_root = Path(getattr(module, 'APPID_ROOT', openappid_update.ROOT))
        self.appid_snapshot = openappid_update.snapshot(self.appid_root)
        self.root = Path(directory).resolve()
        self.directory = Path(tempfile.mkdtemp(prefix='transaction-', dir=self.root))
        self.paths = {}
        paths = list(Path(module.RULES_FILE).parent.glob('*'))
        paths += [Path(getattr(module, name)) for name in
                  ('THRESHOLD_CONF', 'SUPPRESS_LUA', 'DISABLE_CONF', 'DROP_CONF', 'MODIFY_CONF', 'ACTION_CONF')]
        paths.append(group_policy_path(module.THRESHOLD_CONF))
        self.rules_dir = Path(module.RULES_FILE).parent
        self.source_dir = Path(module.SOURCES_DIR)
        paths += list(self.source_dir.rglob('*')) if self.source_dir.exists() else []
        for path in paths:
            if path.is_symlink():
                raise ValueError('symlink in managed rules')
            if path.exists() and not path.is_file():
                continue
            destination = self.directory / str(len(self.paths))
            self.paths[path] = destination if path.exists() else None
            if path.exists():
                shutil.copy2(path, destination)
        manifest = {'rules_dir': str(self.rules_dir), 'sources_snapshot': True, 'openappid': self.appid_snapshot, 'paths': {
            str(path): saved.name if saved else None for path, saved in self.paths.items()}}
        with open(self.directory / 'manifest.json', 'w', encoding='utf-8') as handle:
            json.dump(manifest, handle)
            handle.flush()
            os.fsync(handle.fileno())

    @classmethod
    def load(cls, directory, module):
        import openappid_update
        instance = object.__new__(cls)
        instance.directory = Path(directory)
        instance.root = instance.directory.parent.resolve()
        manifest = json.loads((instance.directory / 'manifest.json').read_text())
        allowed = {Path(getattr(module, name)) for name in
                   ('THRESHOLD_CONF', 'SUPPRESS_LUA', 'DISABLE_CONF', 'DROP_CONF', 'MODIFY_CONF', 'ACTION_CONF')}
        allowed.add(group_policy_path(module.THRESHOLD_CONF))
        instance.rules_dir = Path(module.RULES_FILE).parent
        instance.source_dir = Path(module.SOURCES_DIR)
        instance.appid_root = Path(getattr(module, 'APPID_ROOT', openappid_update.ROOT))
        instance.appid_snapshot = manifest.get('openappid')
        instance.sources_snapshot = manifest.get('sources_snapshot', False)
        instance.paths = {}
        if manifest['rules_dir'] != str(instance.rules_dir):
            raise ValueError('Unexpected rollback rules directory')
        for name, saved in manifest['paths'].items():
            path = Path(name)
            if path not in allowed and path.parent != instance.rules_dir and not path.is_relative_to(instance.source_dir):
                raise ValueError('Unexpected rollback file')
            if saved is not None and (not saved.isdigit() or not (instance.directory / saved).is_file()):
                raise ValueError('Missing rollback file')
            instance.paths[path] = instance.directory / saved if saved else None
        return instance

    def restore(self):
        import openappid_update
        openappid_update.restore(self.appid_snapshot, self.appid_root)
        for path in self.rules_dir.iterdir():
            if path.is_file() and path not in self.paths:
                path.unlink()
        if getattr(self, 'sources_snapshot', True) and self.source_dir.exists():
            for path in self.source_dir.rglob('*'):
                if path.is_file() and path not in self.paths:
                    path.unlink()
        for path, saved in self.paths.items():
            if saved is None:
                path.unlink(missing_ok=True)
            else:
                staged = path.with_name(path.name + '.manager-restore')
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(saved, staged)
                os.replace(staged, path)

    def mark_detector_reload(self):
        with (self.directory/'reload-detectors').open('w') as handle:
            handle.write('required\n');handle.flush();os.fsync(handle.fileno())

    def commit(self, clear_pending=False, applied_manual=None):
        target = self.directory / 'manifest.json'
        manifest = json.loads(target.read_text())
        manifest.update(committed=True, clear_pending=clear_pending)
        if applied_manual:
            manifest['applied_manual'] = applied_manual
        staged = target.with_suffix('.new')
        with open(staged, 'w') as handle:
            json.dump(manifest, handle)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(staged, target)

    def close(self):
        if self.directory.is_symlink() or self.directory.resolve().parent != self.root or not self.directory.name.startswith('transaction-'):
            raise ValueError('Unexpected transaction cleanup path')
        shutil.rmtree(self.directory)


class Jobs:
    """One update/apply/reload at a time; queries and schedule edits stay available."""
    def __init__(self, owner):
        self.owner = owner
        self.local = owner.module.SysInfo()
        self.rule_job = dict(state='idle', started=0, finished=0, lines=deque(maxlen=300))
        self.reload_job = dict(state='idle', last='', since='')

    def __getattr__(self, name):
        return getattr(self.local, name)

    def reload_state(self):
        return dict(self.reload_job)

    def ruleset(self):
        value=self.owner.runtime.engine_reply(['ruleset-stats'])
        return value.get('ruleset-stats',dict(rules_loaded=None,rules_failed=None,rules_skipped=None,error=value.get('__error__','引擎状态正在采样')))

    def engine_call(self,commands,timeout=300):
        with self.owner.runtime.engine_gate:
            return self.local.engine.call(commands,timeout=timeout)

    def update_status(self):
        return dict(self.rule_job, lines=list(self.rule_job['lines'])[-80:], pending=self.owner.drafts.dirty)

    def reload_rules(self):
        return self.start('reload')

    def update_rules(self, offline=False, on_complete=None, trigger='manual'):
        return self.start('apply' if offline else 'update', on_complete, trigger)

    def start(self, kind, on_complete=None, trigger='manual', rule=None):
        with self.owner.lock:
            if self.owner.busy or self.owner.paused:
                return dict(ok=False, error='规则任务正在执行，请稍后重试')
            backup = RuleBackup(self.owner.module, self.owner.state)
            self.owner.busy = True
            job = dict(state='running', kind=kind, trigger=trigger, started=time.time(),
                       finished=0, rc=None, lines=deque(maxlen=300), id=os.urandom(16).hex())
            if rule is not None:
                job['manual_rule'] = rule
            self.rule_job = job
            self.reload_job = dict(state='running', since=time.strftime('%Y-%m-%d %H:%M:%S'))
            try:
                self.owner.runtime.publish_current()
                threading.Thread(target=self.worker, args=(job, backup, on_complete), daemon=True).start()
            except BaseException:
                self.owner.busy = False
                backup.restore()
                backup.close()
                raise
            return dict(ok=True, job_id=job['id'])

    def run(self, arguments, job, timeout=600):
        # Fixed argv only; bounded captured output, deadline covers downloads and validation.
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(arguments, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            position = 0
            deadline = time.monotonic() + timeout
            try:
                while True:
                    with open('/proc/%d/fd/%d' % (os.getpid(), output.fileno()), 'rb') as reader:
                        reader.seek(position)
                        chunk = reader.read(65536)
                    position += len(chunk)
                    if chunk:
                        job['lines'].extend(chunk.decode('utf-8', 'replace').splitlines())
                    if process.poll() is not None and len(chunk) < 65536:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError('规则任务超时')
                    if os.fstat(output.fileno()).st_size > RESPONSE_LIMIT:
                        raise RuntimeError('规则任务输出超过上限')
                    time.sleep(.1)
                if process.returncode:
                    raise RuntimeError('规则命令失败，退出码 %d' % process.returncode)
            finally:
                if process.poll() is None:
                    import signal
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

    def worker(self, job, backup, on_complete):
        m = self.owner.module
        reload_attempted = False
        committed = False
        detectors_changed = False
        applied_manual = None
        guard = ExitStack()
        try:
            guard.enter_context(configuration_lock(m.SNORT_CONF))
            detector=Path(m.BAN_DETECTOR)
            before_detector=detector.read_bytes() if detector.exists() else None
            download_pending = False
            with self.owner.lock:
                if job['kind'] == 'manual-add':
                    ok, message = m.hunt_rule_add(job['manual_rule'])
                    if not ok:
                        raise ValueError(message)
                    applied_manual = Path(m.HUNT_RULES).read_text(encoding='utf-8').splitlines()[-1]
                download_pending = job['kind']=='update' and job['trigger']=='manual' and self.owner.drafts.sources_changed()
                if job['kind'] == 'apply' and self.owner.drafts.dirty:
                    self.owner.drafts.promote()
            if job['kind'] in ('update', 'apply'):
                self.run([m.RULE_UPDATER, *(['--offline'] if job['kind'] == 'apply' else []),
                          *(['--sources-dir',str(self.owner.drafts.sources),'--download-only'] if download_pending else []),
                          '--no-reload'], job)
            if job['kind'] == 'update':
                import openappid_update
                if backup.appid_snapshot is not None:
                    # Journal before any pointer switch, including process crashes.
                    backup.mark_detector_reload()
                    detectors_changed = openappid_update.update(job['lines'], backup.appid_root)
            if download_pending and not detectors_changed and (detector.read_bytes() if detector.exists() else None)==before_detector:
                backup.commit(clear_pending=False);committed=True
                with self.owner.lock:self.owner.drafts.refresh_catalog()
                job['rc']=0;job['lines'].append('所选规则源已下载，点击“应用更改”启用')
                return
            job['lines'].append('开始 Snort 配置校验')
            m.prepare_thresholds()
            # Validate final action rewrites and local/hunting/ban rules together, before reload.
            from session_logger import plugin_arguments
            self.run(['/opt/ips-snort3/3.12.4.0/bin/snort', *plugin_arguments(), '-T', '-c', m.SNORT_CONF], job)
            detectors_changed = detectors_changed or (detector.read_bytes() if detector.exists() else None)!=before_detector
            reload_attempted = True
            job['lines'].append('开始 Snort 热重载')
            if detectors_changed:
                backup.mark_detector_reload()
                result=self.engine_call(['appid-reload-detectors'],timeout=300)
                if 'appid-reload-detectors' not in result:
                    raise RuntimeError(result.get('__error__','AppID 检测器重载失败'))
            if download_pending:
                backup.commit(clear_pending=False);committed=True
                with self.owner.lock:self.owner.drafts.refresh_catalog()
                job['rc']=0;job['lines'].append('所选规则源已下载，点击“应用更改”启用；OpenAppID 更新已完成')
                return
            result = self.engine_call(['ruleset-reload-rules'], timeout=300)
            if 'ruleset-reload-rules' not in result:
                raise RuntimeError(result.get('__error__', '规则重载失败'))
            backup.commit(clear_pending=job['kind'] == 'apply', applied_manual=applied_manual)
            committed = True
            with self.owner.lock:
                if applied_manual:
                    self.owner.drafts.add_applied_manual(applied_manual)
                elif job['kind'] == 'apply' or not self.owner.drafts.dirty:
                    self.owner.drafts.reset()
                else:
                    self.owner.drafts.refresh_catalog()
            job['rc'] = 0
            job['lines'].append('规则已校验并完成热重载')
            if job['kind'] == 'update' and self.owner.drafts.dirty:
                job['lines'].append('待应用更改仍保留，未包含在本次更新中')
        except Exception as exc:
            job['rc'] = 1
            job['lines'].append(str(exc))
            try:
                if committed:
                    job['lines'].append('规则已应用，待应用状态同步失败；重启后台后将恢复状态')
                    backup = None
                    self.owner.paused = True
                else:
                    backup.restore()
                    if reload_attempted:
                        if detectors_changed:
                            result=self.engine_call(['appid-reload-detectors'],timeout=300)
                            if 'appid-reload-detectors' not in result:
                                raise RuntimeError('恢复旧 AppID 检测器失败')
                        result = self.engine_call(['ruleset-reload-rules'], timeout=300)
                        if 'ruleset-reload-rules' not in result:
                            raise RuntimeError('恢复旧规则后的热重载失败')
                    job['lines'].append('已恢复任务开始前的规则文件；待应用更改仍保留')
            except Exception as recovery:
                job['lines'].append('恢复失败：' + str(recovery))
                # Preserve rollback material rather than discard the only known good files.
                backup = None
                self.owner.paused = True
        finally:
            guard.close()
            job.update(state='done', finished=time.time())
            self.reload_job = dict(state='idle', last=time.strftime('%Y-%m-%d %H:%M:%S'),
                                   ok=job['rc'] == 0, error='' if job['rc'] == 0 else job['lines'][-1])
            try:
                if on_complete:
                    on_complete(job)
            finally:
                try:
                    if backup:
                        backup.close()
                finally:
                    with self.owner.lock:
                        self.owner.busy = False
                        self.local.cache.clear()
                    try:self.owner.runtime.publish_current()
                    except OSError:pass  # The periodic publisher retries without rolling back a committed job.


class Manager:
    def __init__(self, module, state='/var/lib/ips-rule-manager'):
        self.module, self.state = module, state
        self.lock = threading.RLock()
        self.busy, self.paused = False, (Path(state)/'maintenance').exists()
        Path(state).mkdir(parents=True, exist_ok=True)
        # No EventDB, event ingestion, authentication or HTTP listener in this process.
        self.jobs = Jobs(self)
        clear_pending = False
        committed_backups = []
        for directory in sorted(Path(state).glob('transaction-*')):
            if directory.is_symlink() or directory.resolve().parent != Path(state).resolve():
                raise ValueError('Unexpected transaction recovery path')
            if not (directory / 'manifest.json').exists():
                shutil.rmtree(directory)
                continue
            manifest = json.loads((directory / 'manifest.json').read_text())
            backup = RuleBackup.load(directory, module)
            if manifest.get('committed'):
                clear_pending = clear_pending or manifest.get('clear_pending', False)
                committed_backups.append(backup)
                continue
            else:
                backup.restore()
                if (backup.directory/'reload-detectors').exists():
                    result=self.jobs.local.engine.call(['appid-reload-detectors'],timeout=300)
                    if 'appid-reload-detectors' not in result:
                        raise RuntimeError('Interrupted AppID transaction recovery failed; backup retained')
                result = self.jobs.local.engine.call(['ruleset-reload-rules'], timeout=300)
                if 'ruleset-reload-rules' not in result:
                    raise RuntimeError('Interrupted rule transaction recovery failed; backup retained')
                self.jobs.rule_job.update(state='done', rc=1, finished=time.time(),
                    lines=deque(['上次规则任务被中断，已恢复任务前规则；待应用更改仍保留'], maxlen=300))
            backup.close()
        from rule_drafts import RuleDrafts
        self.drafts = RuleDrafts(module, state)
        if clear_pending:
            self.drafts.reset()
        for backup in committed_backups:
            manifest = json.loads((backup.directory / 'manifest.json').read_text())
            if manifest.get('applied_manual'):
                self.drafts.add_applied_manual(manifest['applied_manual'])
            backup.close()
        draft = self.drafts.module
        self.app = object.__new__(draft.App)
        self.app.sys, self.app.rules = self.jobs, draft.RuleBook()
        self.app._rule_manager = True
        self.drafts.app = self.app
        self.app.rule_schedule = module.RuleUpdateSchedule(self.jobs)
        self.reads = {name: getattr(draft, name) for name in FUNCTIONS}
        self.reads.update({'app.' + name: getattr(self.app, name) for name in APP_READS})
        self.reads.update({'sys.' + name: getattr(self.jobs, name) for name in SYS_READS})
        self.runtime=RuntimeSnapshot(self)

    def run_schedule(self, stop):
        while not stop.is_set():
            try:
                with self.lock:
                    if not self.paused:
                        self.app.rule_schedule.tick()
            except Exception as exc:
                self.app.rule_schedule.error = '定时更新失败：' + str(exc)
            stop.wait(15)

    def dispatch(self, request, peer_uid=None):
        if not isinstance(request, dict):
            raise ValueError('invalid request')
        operation = request.get('operation')
        if operation == 'history-reset' and set(request) in ({'operation'},{'operation','scope'}):
            import history_reset
            scope=request.get('scope','all')
            if scope not in ('all','database'):raise ValueError('Invalid history reset scope')
            with self.lock:
                if self.busy or self.paused:
                    return dict(ok=False,error='规则或维护任务正在执行，请稍后重试')
                marker=Path(self.state)/'maintenance'
                marker.write_text('history-reset\n');self.paused=True
                try:
                    result=history_reset.queue(self.state,scope=scope)
                    if not result.get('ok'):raise RuntimeError(result.get('error','无法开始清空历史'))
                except Exception:
                    marker.unlink(missing_ok=True);self.paused=False;raise
                self.runtime.publish_current()
                return result
        if operation in ('history-reset-begin','history-reset-finish') and set(request)=={'operation','job'}:
            import history_reset
            if peer_uid!=0:raise ValueError('history reset lifecycle requires a root peer')
            with self.lock:
                value=history_reset.status(self.state)
                if value.get('id')!=request['job'] or not self.paused:raise ValueError('Unknown history reset job')
                if operation=='history-reset-begin':
                    if self.busy or value.get('state')!='queued':raise ValueError('Reset is not ready')
                else:
                    if value.get('state') not in ('done','failed'):raise ValueError('Reset is not finished')
                    (Path(self.state)/'maintenance').unlink(missing_ok=True);self.paused=False
                return dict(ok=True)
        if operation == 'maintenance' and set(request) == {'operation', 'enabled'}:
            if peer_uid != 0 or type(request['enabled']) is not bool:
                raise ValueError('maintenance requires a root peer')
            with self.lock:
                if self.busy:
                    return dict(ok=False, error='A rule task is running')
                marker=Path(self.state)/'maintenance'
                if marker.exists() and marker.read_text().strip()=='history-reset':
                    return dict(ok=False,error='历史清空任务正在执行')
                if request['enabled']:
                    with marker.open('w') as handle:
                        handle.write('paused\n');handle.flush();os.fsync(handle.fileno())
                else:
                    marker.unlink(missing_ok=True)
                self.paused = request['enabled']
                return dict(ok=True)
        if operation == 'ping' and set(request) == {'operation'}:
            return dict(ready=True)
        if operation == 'read' and set(request) == {'operation', 'name', 'args', 'kwargs'}:
            function = self.reads.get(request['name'])
            if function is None or not isinstance(request['args'], list) or not isinstance(request['kwargs'], dict):
                raise ValueError('unsupported query')
            inspect.signature(function).bind(*request['args'], **request['kwargs'])
            if request['name'].startswith('sys.'):
                return function(*request['args'],**request['kwargs'])
            with self.lock:
                from rule_inventory import catalog_view
                with catalog_view():result = function(*request['args'], **request['kwargs'])
                if request['name'] == 'app.rules_payload':
                    result = dict(result, pending=self.drafts.dirty)
                return result
        if operation == 'schedule' and set(request) == {'operation'}:
            return self.app.rule_schedule.status()
        if operation == 'queue' and set(request) == {'operation'}:
            return self.module.nft_query_table('inet', 'ips')
        if operation == 'snort' and set(request) == {'operation', 'commands'}:
            commands = request['commands']
            if not isinstance(commands, list) or not 1 <= len(commands) <= len(ENGINE_READS) or any(
                    not isinstance(c, str) or c not in ENGINE_READS for c in commands):
                raise ValueError('unsupported engine query')
            return self.runtime.engine_reply(commands)
        if operation == 'mutate' and set(request) == {'operation', 'method', 'path', 'body'}:
            method, path, body = (request[k] for k in ('method', 'path', 'body'))
            if not valid_mutation(method, path) or not isinstance(body, dict):
                raise ValueError('unsupported rule operation')
            with self.lock:
                if path == '/api/rules/schedule' and not self.paused:
                    return self.app.rule_schedule.configure(body)
                if self.busy or self.paused:
                    return dict(ok=False, error='规则任务正在执行，请稍后重试')
                if path == '/api/hunt/rules/add-apply':
                    from llm_assistant import validate_rule
                    rule = validate_rule(body.get('rule'))
                    import re
                    used = set()
                    for module in (self.module, self.drafts.module):
                        for key in ('RULES_FILE', 'LOCAL_RULES', 'HUNT_RULES', 'BAN_RULES'):
                            path_value = Path(getattr(module, key))
                            if path_value.exists():
                                with path_value.open(encoding='utf-8') as handle:
                                    for line in handle:
                                        used.update(int(n) for n in re.findall(r'\bsid\s*:\s*(\d+)', line))
                                        if key == 'HUNT_RULES' and re.sub(r'\s*sid\s*:\s*\d+\s*;', '', line).strip() == rule:
                                            return dict(ok=False, error='该规则已在手动规则中，请勿重复添加')
                    sid = 9200001
                    while sid in used:
                        sid += 1
                    rule = rule[:-1] + ' sid:%d;)' % sid
                    result = self.jobs.start('manual-add', rule=rule)
                    return dict(result, sid=sid)
                if path == '/api/actions/apply':
                    return self.jobs.update_rules(offline=True)
                if path == '/api/actions/update':
                    return self.jobs.update_rules()
                if path == '/api/actions/reload':
                    return dict(ok=False, error='请点击“应用更改”提交更改')
                if path == '/api/rules/action-apply':
                    return dict(ok=True, pending=self.drafts.dirty, message='已保存，点击“应用更改”生效')
                if path == '/api/rules/pending/discard':
                    self.drafts.reset()
                    return dict(ok=True, pending=False)
                return self.drafts.mutate(self.jobs, method, path, body)
        raise ValueError('unsupported operation')


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(65)
        try:
            request = receive(self.rfile, REQUEST_LIMIT)
            peer_uid = None
            if hasattr(socket, 'SO_PEERCRED'):
                _pid, peer_uid, _gid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            result = dict(ok=True, result=self.server.manager.dispatch(request, peer_uid=peer_uid))
        except Exception as exc:
            result = dict(ok=False, error=str(exc))
        raw = json.dumps(result, ensure_ascii=False).encode() + b'\n'
        if len(raw) > RESPONSE_LIMIT:
            raw = b'{"ok":false,"error":"response too large"}\n'
        try:
            self.wfile.write(raw)
        except OSError:
            pass


class LocalStreamServer(socketserver.TCPServer):
    # CPython on Windows exposes AF_UNIX but omits socketserver.UnixStreamServer.
    address_family = getattr(socket, 'AF_UNIX', None)

    def server_bind(self):
        self.socket.bind(self.server_address)


class Server(LocalStreamServer):
    MAX_WORKERS = 4
    MAX_QUEUED = 8
    request_queue_size = 16

    def __init__(self, path, manager):
        self.manager = manager
        # Include accepted, queued sockets in the admission budget. The executor
        # keeps only four handlers running, including handlers waiting on the
        # manager lock; a refresh burst does not cause an unread socket close.
        self.slots = threading.BoundedSemaphore(self.MAX_WORKERS+self.MAX_QUEUED)
        self.workers = ThreadPoolExecutor(max_workers=self.MAX_WORKERS,thread_name_prefix='rule-rpc')
        super().__init__(path, RequestHandler)

    def reject_request(self,request):
        # Consume the single bounded request before replying. Closing a socket
        # with unread client data produces ECONNRESET instead of a useful error.
        request.settimeout(.25)
        try:
            with request.makefile('rb') as stream:
                receive(stream,REQUEST_LIMIT)
            request.sendall(json.dumps(dict(ok=False,error='规则管理服务繁忙，请稍后重试'),ensure_ascii=False).encode()+b'\n')
        except (OSError,ValueError):
            pass

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            try:self.reject_request(request)
            finally:self.shutdown_request(request)
            return
        try:
            self.workers.submit(self.process_request_thread,request,address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            self.finish_request(request,address)
        except Exception:
            self.handle_error(request,address)
        finally:
            try:self.shutdown_request(request)
            finally:self.slots.release()

    def server_close(self):
        super().server_close()
        self.workers.shutdown(wait=True)
