"""Compile rule selectors once and apply ordered policy chunks in bounded processes."""
from collections import deque
from concurrent.futures import ProcessPoolExecutor
import fnmatch
import multiprocessing
import os
import re
import time
from urllib.parse import unquote

SID=re.compile(r'\bsid\s*:\s*(\d+)')
GID=re.compile(r'\bgid\s*:\s*(\d+)')
MESSAGE=re.compile(r'\bmsg\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"')
ACTION=re.compile(r'^(alert|block|drop|reject|react|rewrite|log|pass)\s')
NOALERT=re.compile(r'\bflowbits\s*:\s*noalert\s*;')
CHUNK_BYTES=1<<20
PARALLEL_BYTES=8<<20


def worker_count(requested=None):
    available=len(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else os.cpu_count() or 1
    requested=int(os.environ.get('IPS_PULLEDPORK_WORKERS','4')) if requested is None else int(requested)
    return max(1,min(4,available,requested))


class Context:
    def __init__(self,line,groups):
        self.line=line;position=line.find('sid');sid=SID.search(line,position) if position>=0 else None
        position=line.find('gid');gid=GID.search(line,position) if position>=0 else None
        generator=gid[1] if gid else '1';self.generator=int(generator)
        self.sid=sid[1] if sid else '';self.identity=(self.generator,int(self.sid)) if sid else None
        token=(generator+':' if generator!='1' else '')+self.sid
        self.members=groups.get(token,());self._message=None

    @property
    def message(self):
        if self._message is None:
            match=MESSAGE.search(self.line);self._message=match[1] if match else None
        return self._message


class Matcher:
    def __init__(self,values,group_names,source):
        self.ids=set();self.bare_ids=set();self.groups=set();self.messages=[];self.regex=[]
        for selector in values:
            kind,_,value=selector.partition(':')
            if selector.isdigit():self.bare_ids.add(selector)
            elif kind=='sid':
                parts=value.split(':') if ':' in value else ['1',value]
                if len(parts)!=2 or any(not part.isdigit() for part in parts):raise ValueError('Invalid signature selector')
                gid,sid=map(int,parts)
                if not 1<=gid<=8129 or not 1<=sid<=4294967295:raise ValueError('Invalid signature selector')
                self.ids.add((gid,sid))
            elif kind in ('group','group-source'):
                if kind=='group-source':
                    origin,separator,value=value.partition(':')
                    if not separator:raise ValueError('Missing group source')
                    origin,value=unquote(origin,errors='strict'),unquote(value,errors='strict')
                    if not origin or not value or any(c in origin+value for c in '\r\n\0'):raise ValueError('Invalid group selector')
                    if origin!=source:continue
                    value=value.removesuffix('.rules')
                self.groups.update(group for group in group_names if fnmatch.fnmatchcase(group,value) or fnmatch.fnmatchcase(group+'.rules',value))
            elif kind=='msg':self.messages.append((re.compile(fnmatch.translate(value)),value))
            elif kind=='re':self.regex.append(re.compile(value))
            else:raise ValueError('Unsupported rule selector: '+selector)

    def matches(self,context):
        if context.identity in self.ids or context.generator==1 and context.sid in self.bare_ids:return True
        if any(group in self.groups for group in context.members):return True
        if self.messages and context.message is not None and any(pattern.match(context.message) or context.message.startswith(prefix) for pattern,prefix in self.messages):return True
        return any(pattern.search(context.line) for pattern in self.regex)


class Plan:
    def __init__(self,groups,disabled,dropped,rejected,overrides,source):
        names={name for members in groups.values() for name in members}
        self.disabled=Matcher(disabled,names,source);self.dropped=Matcher(dropped,names,source);self.rejected=Matcher(rejected,names,source)
        self.overrides=[]
        for action,selector in overrides:
            if action not in ('drop','block','reject'):raise ValueError('Invalid action override')
            self.overrides.append(('block' if action=='drop' else action,Matcher([selector],names,source)))

    def scans_text(self):
        return any(matcher.regex or matcher.messages for matcher in [self.disabled,self.dropped,self.rejected,*[matcher for _,matcher in self.overrides]])

    def apply(self,line,groups):
        if not ACTION.match(line):return line
        context=Context(line,groups)
        if self.disabled.matches(context):return '# '+line
        action=None
        dropped=self.dropped.matches(context);rejected=self.rejected.matches(context)
        if (dropped or rejected) and not ('noalert' in line and NOALERT.search(line)):
            action='reject' if rejected else 'block'
        for target,matcher in self.overrides:
            if matcher.matches(context):action=target;break
        return ACTION.sub(action+' ',line,count=1) if action else line


def chunks(lines,budget=CHUNK_BYTES):
    batch=[];size=0
    for line in lines:
        weight=len(line.encode('utf-8'))+1
        if batch and size+weight>budget:yield batch;batch=[];size=0
        batch.append(line);size+=weight
    if batch:yield batch


def _initialize(plan,groups):
    global _plan,_groups
    _plan,_groups=plan,groups


def _apply_chunk(lines):
    started=time.process_time()
    return [_plan.apply(line,_groups) for line in lines],os.getpid(),time.process_time()-started


def apply_policy(text,groups,disabled=(),dropped=(),rejected=(),overrides=(),source=None,workers=None,stats=None):
    lines=text.replace('\\\n','').splitlines()
    if not (disabled or dropped or rejected or overrides):return '\n'.join(lines)+'\n'
    plan=Plan(groups,disabled,dropped,rejected,overrides,source)
    count=worker_count(workers);output=[];pids=set();cpu=0.;tasks=0
    if workers is None and not plan.scans_text():count=1
    if count==1 or len(text)<PARALLEL_BYTES:
        started=time.process_time();output=[plan.apply(line,groups) for line in lines];cpu=time.process_time()-started
    else:
        # Each spawned process owns its plan. Queue only one text chunk per worker.
        with ProcessPoolExecutor(max_workers=count,mp_context=multiprocessing.get_context('spawn'),initializer=_initialize,initargs=(plan,groups)) as pool:
            iterator=iter(chunks(lines));pending=deque()
            for _ in range(count):
                batch=next(iterator,None)
                if batch is not None:pending.append(pool.submit(_apply_chunk,batch))
            while pending:
                result,pid,spent=pending.popleft().result();output.extend(result);pids.add(pid);cpu+=spent;tasks+=1
                batch=next(iterator,None)
                if batch is not None:pending.append(pool.submit(_apply_chunk,batch))
    if stats is not None:stats.update(processes=len(pids) or 1,chunks=tasks or 1,worker_cpu_seconds=cpu)
    return '\n'.join(output)+'\n'
