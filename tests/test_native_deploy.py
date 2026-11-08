"""Native activation archives and console-only rollback boundaries."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import zipfile
import unittest
import sys
import types
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]


def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class ArchiveTests(unittest.TestCase):
    def setUp(self): self.deploy=load('deploy-snort3')

    def test_only_pinned_runtime_paths_and_local_links_are_allowed(self):
        for name,link in (('../etc/passwd',None),('/etc/passwd',None),('opt/ips-pulledpork3/other/a.py',None),
                          ('opt/ips-snort3/3.12.4.0/lib/link','../../etc/passwd')):
            with self.subTest(name=name), tempfile.TemporaryFile() as stream:
                with tarfile.open(fileobj=stream,mode='w') as archive:
                    entry=tarfile.TarInfo(name)
                    if link:entry.type=tarfile.SYMTYPE;entry.linkname=link
                    archive.addfile(entry,io.BytesIO())
                stream.seek(0)
                with tarfile.open(fileobj=stream) as archive,self.assertRaises(ValueError):
                    self.deploy.engine_members(archive)

    def test_initial_configuration_preserves_auth_and_uses_fresh_native_store(self):
        original=dict(password_pbkdf2='fixture',port=9000,event_db='/old/events.db',asset_db='/old/assets.db')
        current=self.deploy.console_configuration(original)
        self.assertEqual(current['password_pbkdf2'],original['password_pbkdf2'])
        self.assertEqual(current['asset_db'],original['asset_db'])
        self.assertEqual(current['event_db'],'/var/lib/ips-snort-web/snort-ndr.db')
        self.assertEqual(current['port'],9000)
        self.assertEqual(current['static_dir'],'/usr/local/share/ips-snort-web')
        self.assertEqual(original['event_db'],'/old/events.db')

    def test_separate_units_preserve_isolation_without_fixed_cpu_topology(self):
        detector=self.deploy.render_unit('ips.service',(ROOT/'ips.service').read_text())
        web=self.deploy.render_unit('isolation',(ROOT/'ips-web-isolated.conf').read_text())
        manager=self.deploy.render_unit('manager',(ROOT/'ips-rule-manager.service').read_text())
        self.assertIn('ExecStart=/opt/ips-console/bin/ips-supervisor',detector)
        self.assertNotIn('AllowedCPUs=',detector)
        self.assertNotIn('CPUAffinity=',detector)
        self.assertIn('ips-legacy.service',detector)
        self.assertIn('StateDirectory=ips-snort-web',web)
        self.assertIn('ips-web.conf:/etc/ips-snort-web.conf',web)
        self.assertIn('StateDirectory=ips-snort-rule-manager',manager)
        self.assertNotIn('AllowedCPUs=',manager)
        self.assertNotIn('/usr/local/bin/',detector+web+manager)

    def test_unlisted_archive_files_fail_inventory_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'runtime.tar'
            with tarfile.open(archive,'w') as output:
                for name,data in [('opt/ips-snort3/3.12.4.0/extra',b'unknown'),('ENGINE_SHA256SUMS.json',b'{}')]:
                    item=tarfile.TarInfo(name);item.size=len(data);output.addfile(item,io.BytesIO(data))
            with self.assertRaisesRegex(ValueError,'inventory'):
                self.deploy.unpack_engine(archive,root/'stage')


class ConsoleUpdateTests(unittest.TestCase):
    def test_engine_version_upgrade_requires_release_pins_and_preserves_target_abi(self):
        with mock.patch.dict(sys.modules,{'fcntl':types.SimpleNamespace()} if sys.platform=='win32' else {}):
            module=load('deploy-session-engine')
        expected=json.loads((ROOT/'build_tools/snort-sources.json').read_text())
        previous={'sources':dict(expected,snort={'version':'previous'})}
        manifest=dict(sources=expected,session_patch='ndr-session-2')
        module.validate_upgrade_sources(manifest,previous,expected)
        module.validate_upgrade_sources(dict(manifest,session_patch='ndr-session-3'),previous,expected)
        for key in ('snort','libdaq','target'):
            with self.subTest(source=key):
                altered=dict(expected);altered[key]={}
                with self.assertRaisesRegex(ValueError,'pinned'):
                    module.validate_upgrade_sources(dict(manifest,sources=altered),previous,expected)
        with self.assertRaisesRegex(ValueError,'ABI'):
            module.validate_upgrade_sources(manifest,{'sources':{'target':{}}},expected)

    @unittest.skipIf(sys.platform=='win32','The engine deployment uses Linux absolute runtime paths')
    def test_full_runtime_switch_and_failures_restore_libraries_lua_and_configuration(self):
        import deployment_support as ips_control
        for failure in ('none','startup','rename'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                module=load('deploy-session-engine');root=Path(temporary)
                prefix=root/'runtime';release=root/'release';program=root/'program'
                backups=root/'backups';stage=root/'staging';static=root/'static'
                for path in (prefix/'bin',prefix/'lib',prefix/'etc/snort',release/'build_tools',program,stage,static):path.mkdir(parents=True)
                expected=json.loads((ROOT/'build_tools/snort-sources.json').read_text())
                (release/'build_tools/snort-sources.json').write_text(json.dumps(expected))
                (release/'RELEASE').write_text('fixture')
                for name in ('bin/snort','lib/libdaq.so.3','etc/snort/snort.lua'):(prefix/name).write_text('old '+name)
                (prefix/'engine-manifest.json').write_text(json.dumps({'sources':dict(expected,snort={'version':'old'})}))
                (program/'ips-web').write_text('old web');(static/'index.html').write_text('old ui')
                (program/'backend-build.json').write_text('old backend manifest')
                (release/'backend-build.json').write_text('candidate backend manifest')
                config=root/'snort.lua';config.write_text("local common = 'ts uid session_id '\n-- alert_suppressed\n")
                web=root/'web.json';web.write_text('{"authentication":"fixture"}')
                layout=root/'layout.json';layout.write_text('{}')
                database=root/'events.db';database.write_bytes(b'preserved data')
                def unpack(_,destination):
                    candidate=destination/str(prefix).lstrip('/')
                    for name in ('bin/snort','lib/libdaq.so.3','etc/snort/snort.lua'):
                        path=candidate/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('new '+name)
                    manifest=dict(sources=expected,session_patch='ndr-session-2',sha256=hashlib.sha256(b'new bin/snort').hexdigest())
                    (candidate/'engine-manifest.json').write_text(json.dumps(manifest));return {}
                active=types.SimpleNamespace(unpack_engine=unpack,private_json=lambda p,v:p.write_text(json.dumps(v)))
                def apply(*args):
                    (program/'ips-web').write_text('new web')
                    (program/'backend-build.json').write_text('new backend manifest')
                    if failure=='startup':raise RuntimeError('candidate startup failed')
                native=types.SimpleNamespace(PROGRAMS=('ips-web',),apply=apply)
                modules={'deploy-snort3':active,'deploy-native-backend':native,
                    'deploy-backend':types.SimpleNamespace(wait_ready=mock.Mock()),'deploy-angular':types.SimpleNamespace(snapshot=mock.Mock())}
                client=mock.Mock();client.request.return_value={'ok':True}
                rename=Path.rename
                def move(path,target):
                    if failure=='rename' and '.upgrade-session-' in path.name:raise OSError('candidate rename failed')
                    return rename(path,target)
                with mock.patch.multiple(module,PREFIX=prefix,PROGRAM=program,BACKUPS=backups,STATE=stage,CONFIG=config,
                    WEB_CONFIG=web,STATIC=static,LAYOUT=layout,SESSION_RECEIPT=root/'receipt',ROTATION=root/'rotation'), \
                    mock.patch.object(module,'load',side_effect=lambda _,name:modules[name]),mock.patch.object(module,'run'), \
                    mock.patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout='',stderr='')), \
                    mock.patch.object(module,'ready_engine'),mock.patch.object(module,'resume_manager'), \
                    mock.patch.object(ips_control,'Client',return_value=client),mock.patch.object(Path,'rename',move):
                    if failure=='none':
                        module.upgrade(release,root/'engine.tar')
                        self.assertEqual((prefix/'lib/libdaq.so.3').read_text(),'new lib/libdaq.so.3')
                        module.rollback(next(backups.iterdir()))
                    else:
                        with self.assertRaisesRegex((RuntimeError,OSError),'failed'):module.upgrade(release,root/'engine.tar')
                for name in ('bin/snort','lib/libdaq.so.3','etc/snort/snort.lua'):
                    self.assertEqual((prefix/name).read_text(),'old '+name)
                self.assertEqual((program/'ips-web').read_text(),'old web')
                self.assertEqual((program/'backend-build.json').read_text(),'old backend manifest')
                self.assertEqual(json.loads(web.read_text()),{'authentication':'fixture'})
                self.assertEqual(database.read_bytes(),b'preserved data')

    def test_engine_upgrade_enables_suppressed_block_field_on_existing_notice(self):
        with mock.patch.dict(sys.modules,{'fcntl':types.SimpleNamespace()} if sys.platform=='win32' else {}):
            module=load('deploy-session-engine')
        previous="local common = 'ts uid session_id '\n" \
                 "{ service = 'notice', on_events = 'ips_logging', fields = common .. 'sid rev' }\n"
        candidate=module.extractor_config(previous,'ndr-session-2')
        self.assertIn("get_module_version('extractor', 'inspector') >= 1 and 'alert_suppressed '",candidate)
        self.assertTrue(candidate.endswith(".. common .. 'sid rev' }\n"))
        self.assertEqual(module.extractor_config(candidate,'ndr-session-2'),candidate)
        self.assertEqual(module.extractor_config(previous,'ndr-session-1'),previous)
        with self.assertRaisesRegex(ValueError,'notice'):
            module.extractor_config("local common = 'ts uid session_id '\n",'ndr-session-2')

    def test_session_engine_rollback_restores_engine_modules_static_and_keeps_data(self):
        with mock.patch.dict(sys.modules,{'fcntl':types.SimpleNamespace()} if sys.platform=='win32' else {}):
            module=load('deploy-session-engine')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);backups=root/'backups';backup=backups/'session-fixture';backup.mkdir(parents=True)
            program=root/'program';program.mkdir();prefix=root/'runtime';(prefix/'bin').mkdir(parents=True)
            config=root/'snort.lua';web=root/'web.json';layout=root/'layout.json'
            receipt=root/'session-logger.json';rotation=root/'logrotate.conf'
            static=root/'static';static.mkdir();(static/'index.html').write_text('new-ui')
            previous=backup/'static-before';previous.mkdir();(previous/'index.html').write_text('old-ui')
            data=root/'events.db';data.write_bytes(b'untouched database')
            files={}
            targets=[config,web,layout,receipt,rotation,prefix/'bin/snort',prefix/'engine-manifest.json',program/'ips-web',program/'ips-supervisor']
            for i,path in enumerate(targets):
                path.write_text('new');name='saved-'+str(i);(backup/name).write_text('old');files[str(path)]=name
            extra=program/'native_rules.py';extra.write_text('added');files[str(extra)]=None
            (backup/'state.json').write_text(json.dumps(dict(files=files,home_timer=True)))
            with mock.patch.multiple(module,BACKUPS=backups,PROGRAM=program,PREFIX=prefix,CONFIG=config,WEB_CONFIG=web,LAYOUT=layout,STATIC=static,
                                     SESSION_RECEIPT=receipt,ROTATION=rotation), \
                    mock.patch.object(module,'run'),mock.patch.object(module.subprocess,'run'), \
                    mock.patch.object(module,'ready_engine'),mock.patch.object(module,'resume_manager'):
                module.rollback(backup)
            self.assertTrue(all(path.read_text()=='old' for path in targets))
            self.assertEqual((static/'index.html').read_text(),'old-ui')
            self.assertFalse(extra.exists())
            self.assertEqual(data.read_bytes(),b'untouched database')


    def test_backend_readiness_waits_for_manager_socket_after_http_is_ready(self):
        module=load('deploy-native-backend');client=mock.Mock()
        client.request.side_effect=[FileNotFoundError('starting'),{'ready':True}]
        with mock.patch.object(module,'Client',return_value=client),mock.patch.object(module.time,'sleep') as sleep:
            module.wait_manager()
        self.assertEqual(client.request.call_count,2)
        sleep.assert_called_once_with(.1)




if __name__=='__main__': unittest.main()
