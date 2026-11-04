"""Bounded, ordered CPU work using spawned processes, shared within one service."""
import atexit
from collections import deque
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from concurrent.futures.process import BrokenProcessPool
import multiprocessing
import os
import threading


def worker_count(requested=None):
    try:
        available = len(os.sched_getaffinity(0))
    except AttributeError:
        available = os.cpu_count() or 1
    try:
        limit = int(os.environ.get('IPS_CPU_WORKERS', '4') if requested is None else requested)
    except (TypeError, ValueError):
        raise ValueError('IPS_CPU_WORKERS must be an integer') from None
    return max(1, min(4, available, limit))


def _initialize():
    os.environ['IPS_CPU_CHILD'] = '1'


def _invoke(function, argument):
    return os.getpid(), function(argument)


class CPUExecutor:
    def __init__(self, workers=None):
        self.workers = worker_count(workers)
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(self.workers*2)
        self.stop = threading.Event()
        self.executor = None

    def _submit(self, function, argument):
        while not self.slots.acquire(timeout=.1):
            if self.stop.is_set():
                raise RuntimeError('计算服务正在关闭')
        executor=None
        try:
            with self.lock:
                if self.stop.is_set():
                    raise RuntimeError('计算服务正在关闭')
                if self.executor is None:
                    self.executor = ProcessPoolExecutor(max_workers=self.workers,
                        mp_context=multiprocessing.get_context('spawn'), initializer=_initialize)
                executor=self.executor
                future = executor.submit(_invoke, function, argument)
            future.add_done_callback(lambda _: self.slots.release())
            return future,executor
        except BrokenProcessPool:
            self.slots.release()
            self._reset_broken(executor)
            raise
        except BaseException:
            self.slots.release()
            raise

    def _reset_broken(self, executor):
        with self.lock:
            if executor is None or self.executor is not executor:return
            self.executor=None
        executor.shutdown(wait=False,cancel_futures=True)

    def ordered(self, function, arguments, stats=None, cancelled=None):
        """At most one outstanding batch per worker in each ordered pipeline."""
        if self.workers == 1 or os.environ.get('IPS_CPU_CHILD') == '1':
            for argument in arguments:
                if self.stop.is_set() or (cancelled is not None and cancelled()):
                    raise RuntimeError('计算服务正在关闭')
                if stats is not None:
                    stats.setdefault('pids', set()).add(os.getpid())
                yield function(argument)
            return
        pending = deque()
        source = iter(arguments)
        try:
            for _ in range(self.workers):
                if self.stop.is_set() or (cancelled is not None and cancelled()):
                    raise RuntimeError('计算任务已中断，请重试或缩小时间范围')
                try:
                    pending.append(self._submit(function, next(source)))
                except StopIteration:
                    break
            while pending:
                future,owner=pending.popleft()
                while True:
                    if self.stop.is_set() or (cancelled is not None and cancelled()):
                        future.cancel()
                        raise RuntimeError('计算任务已中断，请重试或缩小时间范围')
                    try:
                        pid,value=future.result(timeout=.1)
                        break
                    except TimeoutError:
                        continue
                    except BrokenProcessPool:
                        self._reset_broken(owner)
                        raise
                if stats is not None:
                    stats.setdefault('pids', set()).add(pid)
                yield value
                try:
                    pending.append(self._submit(function, next(source)))
                except StopIteration:
                    pass
        finally:
            for future,_ in pending:
                future.cancel()
            if hasattr(source,'close'):
                source.close()

    def close(self):
        self.stop.set()
        with self.lock:
            executor, self.executor = self.executor, None
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)


_shared = None
_lock = threading.Lock()


def shared_cpu():
    global _shared
    with _lock:
        if _shared is None or _shared.stop.is_set():
            _shared = CPUExecutor()
            atexit.register(_shared.close)
        return _shared


def byte_batches(items, size=lambda item: len(item), budget=256 << 10):
    batch, weight = [], 0
    for item in items:
        current = size(item)
        if batch and weight+current > budget:
            yield batch
            batch, weight = [], 0
        batch.append(item)
        weight += current
    if batch:
        yield batch
