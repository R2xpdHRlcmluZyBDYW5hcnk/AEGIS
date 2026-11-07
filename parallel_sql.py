"""Independent SQLite readers pinned to one writer-coordinated WAL snapshot."""
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import ExitStack
from pathlib import Path
import queue
import sqlite3
import threading


class ReadExecutor:
    """Borrow up to three helper threads; concurrent requests never wait for a lease."""
    def __init__(self, helpers=3):
        self.workers = max(0, min(3, helpers))
        self.slots = threading.BoundedSemaphore(self.workers)
        self.stop = threading.Event()
        self.lease_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max(1,self.workers), thread_name_prefix='sqlite-read')

    def snapshot(self, source, connection, setup=None, cancelled=None, locks=()):
        return Snapshot(self, source, connection, setup, cancelled, locks)

    def close(self):
        self.stop.set()
        # Reserved snapshot workers must run their finally blocks to release leases.
        # Their bounded input queues are drained without executing further SQL.
        self.executor.shutdown(wait=True, cancel_futures=False)

    def release(self, member):
        with self.lease_lock:
            if member.pop('lease', False):
                self.slots.release()


class Snapshot:
    def __init__(self, pool, source, connection, setup, cancelled, locks):
        self.pool, self.source, self.connection = pool, source, connection
        self.setup, self.cancelled, self.locks = setup, cancelled, locks
        self.stop = threading.Event()
        self.members = []

    def _cancelled(self):
        return (self.stop.is_set() or self.pool.stop.is_set()
                or (self.cancelled is not None and self.cancelled()))

    @staticmethod
    def _pin(conn):
        if not conn.in_transaction:
            conn.execute('BEGIN')
        # SQLite begins a read snapshot on the first actual database access.
        for _, name, _ in conn.execute('PRAGMA database_list'):
            if name not in ('main','summaries'):
                raise ValueError('Unexpected attached query database')
            conn.execute('SELECT name FROM '+name+'.sqlite_master LIMIT 1').fetchone()

    def _worker(self, member, attachments):
        conn = None
        try:
            conn = sqlite3.connect(Path(self.source.path).resolve().as_uri()+'?mode=ro',uri=True,timeout=1)
            conn.execute('PRAGMA query_only=ON')
            conn.execute('PRAGMA cache_size=-2048')
            for name, path in attachments:
                conn.execute('ATTACH DATABASE ? AS '+name,(Path(path).resolve().as_uri()+'?mode=ro',))
                conn.execute('PRAGMA '+name+'.cache_size=-2048')
            conn.set_progress_handler(self._cancelled, 10000)
            if self.setup is not None:
                self.setup(conn)
            self._pin(conn)
            member['ready'].set()
            while not self._cancelled():
                try:
                    job = member['queue'].get(timeout=.1)
                except queue.Empty:
                    continue
                if job is None:
                    break
                statement, args, future = job
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    future.set_result(conn.execute(statement,args).fetchall())
                except BaseException as exc:
                    future.set_exception(exc)
        except BaseException as exc:
            member['error'] = exc
        finally:
            member['ready'].set()
            while True:
                try:
                    job = member['queue'].get_nowait()
                except queue.Empty:
                    break
                if job is not None:
                    if job[2].set_running_or_notify_cancel():
                        job[2].set_exception(sqlite3.OperationalError('interrupted'))
            if conn is not None:
                conn.set_progress_handler(None,0)
                conn.close()
            self.pool.release(member)

    def __enter__(self):
        try:
            attachments = [(name,path) for _,name,path in self.connection.execute('PRAGMA database_list') if name!='main']
            if any(name!='summaries' for name,_ in attachments):
                raise ValueError('Unexpected attached query database')
            # Reserve before taking the writer lock, so a busy pool never stalls ingestion.
            while len(self.members)<self.pool.workers and self.pool.slots.acquire(blocking=False):
                self.members.append(dict(queue=queue.Queue(maxsize=1),ready=threading.Event(),error=None,future=None,lease=True))
            with ExitStack() as stack:
                for lock in self.locks or (self.source.lock,):
                    if not lock.acquire(blocking=False):
                        # WAL readers remain available while ingestion owns its lock.
                        # A single connection already supplies a consistent snapshot.
                        for member in self.members:
                            self.pool.release(member)
                        self.members.clear()
                        self._pin(self.connection)
                        return self
                    stack.callback(lock.release)
                self._pin(self.connection)
                for member in self.members:
                    try:
                        member['future'] = self.pool.executor.submit(self._worker,member,attachments)
                    except BaseException:
                        self.pool.release(member)
                        member['ready'].set()
                        raise
                for member in self.members:
                    if not member['ready'].wait(timeout=2):
                        raise RuntimeError('Parallel read snapshot initialization timed out')
                    if member['error'] is not None:
                        raise member['error']
            return self
        except BaseException:
            self.close()
            raise

    def fetch(self, statements):
        """Return results in statement order; each helper owns its own connection."""
        statements = iter(statements)
        result = []
        while True:
            jobs = []
            for member in self.members:
                try:
                    statement, args = next(statements)
                except StopIteration:
                    break
                if self._cancelled() or member['future'].done():
                    raise sqlite3.OperationalError('interrupted')
                future = Future()
                member['queue'].put_nowait((statement,args,future))
                jobs.append(future)
            try:
                statement, args = next(statements)
            except StopIteration:
                own = None
            else:
                if self._cancelled():
                    raise sqlite3.OperationalError('interrupted')
                own = self.connection.execute(statement,args).fetchall()
            for future in jobs:
                while True:
                    if self._cancelled():
                        raise sqlite3.OperationalError('interrupted')
                    try:
                        result.append(future.result(timeout=.1))
                        break
                    except FutureTimeout:
                        continue
            if own is not None:
                result.append(own)
            if not jobs and own is None:
                return result

    def close(self):
        self.stop.set()
        for member in self.members:
            if member['future'] is None:
                self.pool.release(member)
                continue
            try:
                member['queue'].put_nowait(None)
            except queue.Full:
                pass
        for member in self.members:
            if member['future'] is not None:
                if member['future'].cancelled():self.pool.release(member)
                else:member['future'].result(timeout=5)
        self.members.clear()

    def __exit__(self,*_):
        self.close()


def fetch_many(connection, statements, parallel=None):
    if parallel is not None:
        return parallel.fetch(statements)
    return [connection.execute(statement,args).fetchall() for statement,args in statements]
