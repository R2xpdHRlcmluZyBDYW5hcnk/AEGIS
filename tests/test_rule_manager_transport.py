"""Local socket bursts must queue within bounds and report overload explicitly."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import ips_control as control


class SlowManager:
    def __init__(self):
        self.release=threading.Event()
        self.condition=threading.Condition()
        self.active=self.maximum=self.calls=0

    def dispatch(self,request,peer_uid=None):
        with self.condition:
            self.active+=1;self.calls+=1
            self.maximum=max(self.maximum,self.active)
            self.condition.notify_all()
        try:
            if not self.release.wait(5):raise RuntimeError('synthetic request timed out')
            return dict(ready=True)
        finally:
            with self.condition:self.active-=1


@unittest.skipUnless(hasattr(socket,'AF_UNIX'),'Unix sockets unavailable')
class RuleTransportCase(unittest.TestCase):
    def test_refresh_burst_queues_after_four_workers_without_resetting_connections(self):
        manager=SlowManager()
        with tempfile.TemporaryDirectory(prefix='ips-rpc-') as temporary:
            path=str(Path(temporary)/'control.sock')
            with control.Server(path,manager) as server,ThreadPoolExecutor(max_workers=8) as clients:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                futures=[]
                try:
                    futures.extend(clients.submit(control.Client(path).request,'ping') for _ in range(4))
                    with manager.condition:self.assertTrue(manager.condition.wait_for(lambda:manager.active==4,2))
                    futures.extend(clients.submit(control.Client(path).request,'ping') for _ in range(4))
                    # Hold the first wave until the server has received the second.
                    self.assertFalse(manager.release.wait(.2))
                    manager.release.set()
                    self.assertTrue(all(future.result(timeout=5)['ready'] for future in futures))
                    self.assertEqual(manager.calls,8)
                    self.assertEqual(manager.maximum,4)
                finally:
                    manager.release.set();server.shutdown();thread.join()

    def test_excess_mutation_returns_busy_without_dispatch_or_connection_reset(self):
        manager=SlowManager()
        with tempfile.TemporaryDirectory(prefix='ips-rpc-') as temporary, \
             mock.patch.object(control.Server,'MAX_WORKERS',1,create=True), \
             mock.patch.object(control.Server,'MAX_QUEUED',1,create=True):
            path=str(Path(temporary)/'control.sock')
            with control.Server(path,manager) as server,ThreadPoolExecutor(max_workers=1) as clients:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                queued=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    first=clients.submit(control.Client(path).request,'ping')
                    with manager.condition:self.assertTrue(manager.condition.wait_for(lambda:manager.active==1,2))
                    queued.connect(path);queued.sendall(b'{"operation":"ping"}\n')
                    with self.assertRaisesRegex(RuntimeError,'繁忙'):
                        control.Client(path).request('mutate',method='POST',path='/api/actions/apply',body={})
                    self.assertEqual(manager.calls,1)
                    manager.release.set()
                    self.assertTrue(first.result(timeout=5)['ready'])
                    queued.settimeout(5)
                    with queued.makefile('rb') as stream:self.assertTrue(json.loads(stream.readline())['result']['ready'])
                    self.assertEqual(manager.calls,2)
                finally:
                    manager.release.set();queued.close();server.shutdown();thread.join()


if __name__=='__main__':unittest.main()
