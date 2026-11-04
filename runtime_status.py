"""Bounded background telemetry and an atomic, read-only Web status snapshot."""
import copy
import json
import os
from pathlib import Path
import threading
import time

ENGINE_READS = frozenset(('version','uptime','running-mode','capture-mode',
                         'ruleset-reload-time','ruleset-stats','dump-counters'))
LIMIT = 16 << 20


class RuntimeReader:
    def __init__(self,path):
        self.path=Path(path)
        self.lock=threading.Lock()
        self.signature=None
        self.value={}

    def read(self):
        error=''
        with self.lock:
            try:
                with self.path.open('rb') as handle:
                    info=os.fstat(handle.fileno())
                    signature=(info.st_ino,info.st_mtime_ns,info.st_size)
                    if signature!=self.signature:
                        raw=handle.read(LIMIT+1)
                        if len(raw)>LIMIT:raise ValueError('status snapshot exceeds limit')
                        value=json.loads(raw)
                        if not isinstance(value,dict) or value.get('schema')!=1:raise ValueError('invalid status snapshot')
                        self.value,self.signature=value,signature
            except (OSError,ValueError):
                error='运行状态快照暂不可用'
            result=copy.deepcopy(self.value)
        metadata=result.setdefault('telemetry',{})
        stamp=metadata.get('as_of',0)
        publication=result.get('published',0)
        metadata['stale']=bool(error or metadata.get('updating') or not stamp or time.time()-stamp>10 or time.time()-publication>5)
        if error:metadata['error']=error
        elif time.time()-publication>5:metadata['error']='运行状态采样已延迟'
        return result

    def engine_call(self,commands,timeout=10):
        if not isinstance(commands,list) or not commands or any(command not in ENGINE_READS for command in commands):
            raise ValueError('unsupported engine query')
        value=self.read();engine=value.get('engine',{})
        result={command:engine[command] for command in commands if command in engine}
        error=value.get('telemetry',{}).get('error')
        if error or any(command not in result for command in commands):
            result['__error__']=error or '引擎状态正在采样'
        return result


class RuntimeSnapshot:
    """One sampler, one publisher; neither request reads nor jobs wait for sampling."""
    def __init__(self,manager):
        self.manager=manager
        self.lock=threading.Lock()
        self.engine_gate=threading.Lock()
        self.publish_lock=threading.Lock()
        self.path=None
        self.engine={}
        self.service={}
        self.queue_table=None
        self.as_of=0
        self.error='引擎状态正在采样'

    def engine_reply(self,commands):
        with self.lock:
            result={command:copy.deepcopy(self.engine[command]) for command in commands if command in self.engine}
            if self.error or len(result)!=len(commands):result['__error__']=self.error or '引擎状态正在采样'
            return result

    def payload(self):
        with self.lock:
            result=dict(schema=1,published=time.time(),engine=copy.deepcopy(self.engine),
                        service=copy.deepcopy(self.service),queue_table=copy.deepcopy(self.queue_table),
                        telemetry=dict(as_of=self.as_of,error=self.error,updating=self.manager.busy))
        result.update(update_status=self.manager.jobs.update_status(),reload_state=self.manager.jobs.reload_state())
        from history_reset import status
        result['history_reset']=status(self.manager.state)
        return result

    def sample(self):
        manager=self.manager
        from session_logger import ensure_loaded
        ensure_loaded(manager)
        service=manager.jobs.local.service()
        table=manager.module.nft_query_table('inet','ips')
        with self.lock:self.service,self.queue_table=service,table
        if manager.busy or getattr(manager,'paused',False):return
        with self.engine_gate:
            if manager.busy or getattr(manager,'paused',False):return
            result=manager.jobs.local.engine.call(sorted(ENGINE_READS),timeout=2)
        if manager.busy or getattr(manager,'paused',False):return
        with self.lock:
            if result.get('__error__'):
                self.error=result['__error__']
            elif any(command not in result for command in ENGINE_READS):
                self.error='引擎状态样本不完整'
            else:
                self.engine=result
                self.as_of=time.time()
                self.error=''

    def publish(self,path):
        with self.publish_lock:
            self._publish(path)

    def publish_current(self):
        if self.path is not None:self.publish(self.path)

    def _publish(self,path):
        path=Path(path);candidate=path.with_suffix('.new')
        raw=json.dumps(self.payload(),ensure_ascii=False,separators=(',',':')).encode()
        if len(raw)>LIMIT:raise ValueError('status snapshot exceeds limit')
        try:
            with candidate.open('wb') as handle:
                os.chmod(candidate,0o640)
                handle.write(raw)
            for attempt in range(8):
                try:
                    candidate.replace(path)
                    break
                except PermissionError:
                    if os.name!='nt' or attempt==7:raise
                    time.sleep(.01)  # Windows readers briefly deny rename; Linux uses atomic replace directly.
        finally:candidate.unlink(missing_ok=True)

    def start(self,stop,path):
        # Publish readiness before sampling; the first HTTP request never opens
        # a native control socket, even while the engine is already reloading.
        self.path=Path(path)
        self.publish(path)
        def sample():
            while not stop.is_set():
                try:self.sample()
                except Exception as exc:
                    with self.lock:self.error=str(exc)
                stop.wait(2)
        def publish():
            while not stop.wait(.5):
                try:self.publish(path)
                except OSError:pass
        threads=[threading.Thread(target=sample,name='runtime-sampler',daemon=True),
                 threading.Thread(target=publish,name='runtime-publisher',daemon=True)]
        for thread in threads:thread.start()
        return threads
