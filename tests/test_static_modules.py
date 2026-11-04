"""Serve the production module graph through the real authenticated HTTP handler."""
import hashlib
import http.client
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import threading
import types
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('static_modules_backend', str(ROOT / 'ips-web'))
spec = importlib.util.spec_from_loader(loader.name, loader)
backend = importlib.util.module_from_spec(spec)
loader.exec_module(backend)


class StaticModuleCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        manifest = ROOT / 'frontend-build.json'
        if manifest.exists():
            self.static = ROOT
            self.files = json.loads(manifest.read_text())['files']
        else:
            self.static = Path(self.temp.name)
            payloads = {
                'index.html': '<ndr-root></ndr-root><script type="module" src="/app.js"></script>',
                'app.js': 'import "./chunk-SHARED123.js"; import("./chunk-CHART123.js");',
                'ui.js': 'export const polyfill = true;',
                'chunk-SHARED123.js': 'export const shared = true;',
                'chunk-CHART123.js': 'import "./chunk-SHARED123.js"; export const chart = true;',
            }
            for name, data in payloads.items():
                (self.static/name).write_text(data)
            self.files = {name: hashlib.sha256((self.static/name).read_bytes()).hexdigest() for name in payloads}
        class Handler(backend.Handler):
            def log_message(self, *_):
                pass
        Handler.config = dict(static_dir=str(self.static))
        Handler.app = types.SimpleNamespace(sessions=types.SimpleNamespace(get=lambda token: {'user':'fixture'} if token=='static-fixture' else None))
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def request(self, name, authenticated=True):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        headers = {'Cookie':'ipsweb_session=static-fixture'} if authenticated else {}
        connection.request('GET', '/'+name, headers=headers)
        response = connection.getresponse()
        result = response.status, dict((k.lower(),v) for k,v in response.getheaders()), response.read()
        connection.close()
        return result

    def test_all_production_modules_have_executable_mime_and_exact_bytes(self):
        modules = [name for name in self.files if name.endswith('.js')]
        self.assertTrue(any(name.startswith('chunk-') for name in modules))
        for name in modules:
            with self.subTest(module=name):
                status, headers, body = self.request(name+'?v=fixture')
                self.assertEqual(status, 200)
                self.assertEqual(headers['content-type'].split(';')[0], 'application/javascript')
                self.assertEqual(headers['x-content-type-options'], 'nosniff')
                self.assertEqual(hashlib.sha256(body).hexdigest(),self.files[name])
                for reference in re.findall(r'''(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["']([^"']+\.js[^"']*)["']''',body.decode()):
                    target=urlsplit(reference).path.removeprefix('./').removeprefix('/')
                    self.assertIn(target,self.files,'Unpublished module dependency: '+reference)

    def test_chunks_remain_authenticated(self):
        for name in self.files:
            if name.startswith('chunk-'):
                status,headers,body=self.request(name,authenticated=False)
                self.assertEqual(status,302)
                self.assertEqual(headers['location'],'/login')
                self.assertEqual(body,b'')


if __name__=='__main__':
    unittest.main()
