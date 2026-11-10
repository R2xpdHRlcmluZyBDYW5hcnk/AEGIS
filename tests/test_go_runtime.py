"""Native runtime installation, detector-sized queues and failed-upgrade rollback."""
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tests.test_native_deploy import load
deploy=load('deploy-supervisor')
from tests.test_deploy_nft import full_table
from tests.test_go_backend import deployer,native_fixture

ROOT=Path(__file__).resolve().parents[1]


def native_program(directory,name,receipt):
    binary=bytearray(64);binary[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',binary,18,183)
    (directory/name).write_bytes(binary)
    value=dict(schema=1,backend='go',target='linux-arm64',go_version='1.27.3',sqlite_version='3.54.1',files={name:hashlib.sha256(binary).hexdigest()})
    (directory/receipt).write_text(json.dumps(value));return value


class NativeRuntimeTests(unittest.TestCase):
    def test_supervisor_manifest_rejects_tampered_or_foreign_programs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);manifest=native_program(root,'ips-supervisor','supervisor-build.json')
            with mock.patch.object(deploy,'run',return_value=json.dumps(dict(backend='go',go_version='go1.27.3'))):
                self.assertEqual(deploy.native_manifest(root),manifest)
                (root/'ips-supervisor').write_bytes(b'#! invalid')
                with self.assertRaises(ValueError):deploy.native_manifest(root)

    def exercise(self,failure):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);release=root/'release';release.mkdir();program=root/'program';program.mkdir()
            native_program(release,'ips-supervisor','supervisor-build.json')
            (release/'deploy-nft.py').write_bytes((ROOT/'deploy-nft.py').read_bytes())
            original=b'#!/usr/bin/python3\n# previous installation fixture\n';(program/'ips-supervisor').write_bytes(original)
            proc=root/'proc/201';proc.mkdir(parents=True);(proc/'cmdline').write_bytes(b'python3\0'+str(program/'ips-supervisor').encode()+b'\0')
            pid=root/'snort.pid';pid.write_text('202');before=full_table();before['nftables'][1]['chain']['prio']=-90
            after=json.loads(json.dumps(before));after['nftables'][-1]['rule']['expr'][-1]['queue']['num']={'range':[0,7]}
            snapshots=iter((before,after));calls=[]
            def run(*args,**kwargs):
                calls.append(args)
                if 'resources' in args:return '{"workers":8}'
                if 'list' in args:return json.dumps(next(snapshots))
                if '--nft-rules' in args:return 'table inet ips { chain prerouting { counter queue flags bypass to 0-7 } }'
                return ''
            ready=mock.Mock(side_effect=[RuntimeError('queue failure'),204] if failure else [204])
            with mock.patch.multiple(deploy,NATIVE_PROGRAM=program,PROC=proc.parent,ENGINE_PID=pid,BACKUPS=root/'backups'),mock.patch.object(deploy,'native_manifest'),mock.patch.object(deploy,'process',side_effect=lambda unit:201 if unit=='ips.service' else 203),mock.patch.object(deploy,'run',side_effect=run),mock.patch.object(deploy,'rule_maintenance',return_value=nullcontext()),mock.patch('deployment_support.configuration_lock',return_value=nullcontext()),mock.patch.object(deploy,'wait_ready',ready),mock.patch('builtins.print'):
                if failure:
                    with self.assertRaisesRegex(RuntimeError,'queue failure'):deploy.upgrade(release)
                else:deploy.upgrade(release)
            self.assertEqual(ready.call_args_list[0].args[0].QUEUE_IDS,frozenset(map(str,range(8))))
            if failure:
                self.assertEqual((program/'ips-supervisor').read_bytes(),original)
                self.assertFalse((program/'supervisor-build.json').exists())
            else:self.assertEqual((program/'ips-supervisor').read_bytes(),(release/'ips-supervisor').read_bytes())
            units=[call for call in calls if call[0]=='systemctl']
            self.assertEqual(units,[('systemctl','restart','ips.service'),('systemctl','stop','ips.service'),('systemctl','start','ips.service')] if failure else [('systemctl','restart','ips.service')])

    def test_native_detector_activation_and_rollback(self):
        self.exercise(False);self.exercise(True)

    def test_service_entries_have_no_runtime_python(self):
        unit=(ROOT/'ips-quic-observer.service').read_text()
        self.assertIn('/opt/ips-console/bin/ips-quic-observer --config',unit)
        self.assertNotIn('/usr/bin/python',unit)
        for path in (ROOT/'backend/internal/console').glob('*.go'):
            if path.name.endswith('_test.go'):continue
            self.assertNotIn('"/usr/bin/python3"',path.read_text(),path.name)

    def test_admin_service_allocations_are_preserved_on_console_update(self):
        module=deployer()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);release=root/'release';installed=root/'installed';release.mkdir();installed.mkdir()
            for name in module.PROGRAMS:
                (release/name).write_text('# helper\n');(installed/name).write_text('# helper\n')
            manifest=native_fixture(release,module)
            for name in (*module.PROGRAMS,'backend-build.json','maintenance-build.json'):(installed/name).write_bytes((release/name).read_bytes())
            config=root/'config';config.write_text('{}')
            source_config=root/'signature-sources.json';source_config.write_bytes((release/source_config.name).read_bytes())
            resources=[]
            for unit in module.RESOURCE_OVERRIDES:
                path=root/'units'/(unit+'.d')/'50-ips-parallel.conf';path.parent.mkdir(parents=True);path.write_bytes(b'[Service]\nCPUQuota=250%\nCPUAffinity=2-3\n');resources.append((path,path.stat().st_mtime_ns))
            runtime=root/'units/ips-web.service.d/70-overview-snapshot.conf';runtime.write_bytes(b'[Service]\nRuntimeDirectory=ips-web-overview\nRuntimeDirectoryMode=0700\n')
            client=mock.Mock();client.request.return_value={'ok':True,'ready':True}
            with mock.patch.multiple(module,CONFIG=config,BIN=installed,BACKUPS=root/'backups',SIGNATURE_SOURCES=root/'signature-sources.json',PIDFILE=root/'pid',RESOURCE_ROOT=root/'units'),mock.patch.object(module,'validate_go_manifest',return_value=manifest),mock.patch.object(module,'Client',return_value=client),mock.patch.object(module.subprocess,'run') as run,mock.patch('builtins.print'):
                module.apply(release,mock.Mock(),{})
            for path,mtime in resources:self.assertEqual(path.stat().st_mtime_ns,mtime)
            run.assert_not_called()

    def test_maintenance_update_switches_quic_entry_and_rolls_back_without_touching_detector(self):
        for failure in (False,True):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                module=deployer();root=Path(temporary);release=root/'release';installed=root/'installed';release.mkdir();installed.mkdir()
                for name in module.PROGRAMS:
                    (release/name).write_text('# candidate helper\n');(installed/name).write_text('# previous helper\n')
                manifest=native_fixture(release,module)
                unit=root/'units/ips-quic-observer.service';unit.parent.mkdir()
                original=(ROOT/'ips-quic-observer.service').read_bytes().replace(b'/opt/ips-console/bin/ips-quic-observer',b'/usr/bin/python3 -B /opt/ips-console/bin/quic_observer.py')
                unit.write_bytes(original);config=root/'config';config.write_text('{}')
                client=mock.Mock();client.request.return_value={'ok':True,'ready':True}
                ready=mock.Mock(side_effect=[RuntimeError('fixture startup failure'),{}] if failure else [dict(sqlite_version='3.54.1',backend='go',go_version='go1.27.3')])
                result=mock.Mock(returncode=0)
                with mock.patch.multiple(module,CONFIG=config,BIN=installed,BACKUPS=root/'backups',SIGNATURE_SOURCES=root/'signature-sources.json',PIDFILE=root/'pid',RESOURCE_ROOT=root/'units'),mock.patch.object(module,'Client',return_value=client),mock.patch.object(module,'validate_go_manifest',return_value=manifest),mock.patch.object(module.subprocess,'run',return_value=result) as run,mock.patch('builtins.print'):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError,'fixture startup failure'):module.apply(release,ready,{})
                    else:module.apply(release,ready,{})
                if failure:
                    self.assertEqual(unit.read_bytes(),original)
                    self.assertFalse((installed/'maintenance-build.json').exists())
                else:
                    self.assertNotIn(b'/usr/bin/python',unit.read_bytes())
                    self.assertEqual((installed/'maintenance-build.json').read_bytes(),(release/'maintenance-build.json').read_bytes())
                stopped=[call.args[0] for call in run.call_args_list if call.args[0][:2]==['systemctl','stop']]
                self.assertTrue(stopped)
                self.assertTrue(all('ips-quic-observer' in call for call in stopped))
                self.assertTrue(all('ips' not in call[2:] for call in stopped))
