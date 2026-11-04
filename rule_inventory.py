"""Shared, bounded parsing cache for rule text; policy state is kept separately."""
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
import re
import tarfile
import threading
import sys
from typing import NamedTuple
from functools import wraps
from parallel_cpu import shared_cpu, byte_batches
import os

ACTION=re.compile(r'^(?:#\s*)?(alert|block|drop|reject\w*|pass)\s')
SID=re.compile(r'\bsid\s*:\s*(\d+)')
GID=re.compile(r'\bgid\s*:\s*(\d+)')
# Consume unescaped runs together instead of backtracking once per character.
MESSAGE=re.compile(r'\bmsg\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"')


class Rule(NamedTuple):
    token:object
    gid:int
    sid:int
    message:str
    line:str
    action:str
    enabled:bool


def parse(raw):
    rows=[]
    text=raw.decode('utf-8','replace').replace('\\\r\n','').replace('\\\n','')
    for text in text.splitlines():
        action=ACTION.match(text)
        if not action:continue
        sid_at=text.find('sid')
        if sid_at<0:continue
        sid=SID.search(text,sid_at)
        if not sid:continue
        gid_at=text.find('gid');gid=GID.search(text,gid_at) if gid_at>=0 else None;gid=int(gid[1]) if gid else 1;sid=int(sid[1])
        line=text.lstrip('# ').strip();message=MESSAGE.search(line)
        token=sid if gid==1 else (gid,sid)
        rows.append(Rule(token,gid,sid,message[1] if message else 'SID '+str(token),line,action[1],not text.startswith('#')))
    return tuple(rows)


def _parse_batch(lines):
    return parse(''.join(lines).encode('utf-8'))


def parse_parallel(raw, pool=None, stats=None):
    if len(raw)<1<<20 or os.environ.get('IPS_CPU_CHILD')=='1':
        return parse(raw)
    # Normalize continuations before choosing complete rule boundaries.
    text=raw.decode('utf-8','replace').replace('\\\r\n','').replace('\\\n','')
    batches=byte_batches(text.splitlines(keepends=True),size=lambda line:len(line.encode('utf-8')))
    return tuple(row for rows in (pool or shared_cpu()).ordered(_parse_batch,batches,stats) for row in rows)


class RuleFiles:
    def __init__(self,limit=128<<20,entries=32):
        self.limit,self.entries=limit,entries
        self.lock=threading.RLock();self.cache=OrderedDict();self.bytes=0

    def read(self,path):
        path=Path(path);info=path.stat()
        signature=(info.st_ino,info.st_mtime_ns,info.st_size)
        with self.lock:
            saved=self.cache.get(str(path))
            if saved and saved[0]==signature:self.cache.move_to_end(str(path));return saved[1]
            groups=[]
            if str(path).endswith(('.tar.gz','.tgz','.tar')):
                with tarfile.open(path,mode='r|*',bufsize=1<<20) as archive:
                    for member in archive:
                        if member.isfile() and member.name.endswith('.rules') and member.size<=128<<20:
                            with archive.extractfile(member) as handle:
                                groups.append((member.name,parse_parallel(handle.read())))
            else:groups.append((path.name,parse_parallel(path.read_bytes())))
            value=tuple(groups)
            weight=sum(sys.getsizeof(row)+sys.getsizeof(row.line)+sys.getsizeof(row.message) for _,rows in value for row in rows)
            if saved:self.bytes-=saved[2];del self.cache[str(path)]
            if weight<=self.limit:
                while self.cache and (self.bytes+weight>self.limit or len(self.cache)>=self.entries):
                    _,old=self.cache.popitem(last=False);self.bytes-=old[2]
                self.cache[str(path)]=(signature,value,weight);self.bytes+=weight
            return value


FILES=RuleFiles()
_view=threading.local()


@contextmanager
def catalog_view():
    """One filesystem inventory per module and read request, including helpers."""
    previous=getattr(_view,'catalogs',None)
    if previous is None:_view.catalogs={}
    try:yield
    finally:
        if previous is None:del _view.catalogs


def pinned(cache):
    snapshots=getattr(_view,'catalogs',None)
    if snapshots is not None and id(cache) in snapshots:return snapshots[id(cache)]


def pin(cache,rows):
    snapshots=getattr(_view,'catalogs',None)
    if snapshots is not None:snapshots[id(cache)]=rows
    return rows


def catalog_read(function):
    @wraps(function)
    def read(*args,**kwargs):
        with catalog_view():return function(*args,**kwargs)
    return read
