"""Detector archives are data until verified; rollback includes the ODP pointer."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import openappid_update as u
from tests import test_rule_manager as fixture


def archive(members=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as package:
        for name,data,kind in members or [('odp/appMapping.data',b'http',None),('odp/lua/http.lua',b'-- detector',None)]:
            entry=tarfile.TarInfo(name);entry.size=len(data)
            if kind:entry.type=kind;entry.linkname='/outside'
            package.addfile(entry,io.BytesIO(data))
    return output.getvalue()


def existing(root):
    previous=root/'releases'/('a'*64);(previous/'lua').mkdir(parents=True)
    (previous/'appMapping.data').write_text('previous')
    try:(root/'odp').symlink_to(previous,target_is_directory=True)
    except OSError:raise unittest.SkipTest('Symbolic links are unavailable')
    return previous


def downloader(data):
    def fetch(url,target=None,maximum=None):
        if url==u.PAGE:return b'<a href="/downloads/openappid/12345">OpenAppID</a>'
        if url==u.CHECKSUM:
            return ('  '+hashlib.md5(data).hexdigest()+' snort-openappid.tar.gz\n  '+'a'*32+' OpenDetectorDeveloperGuide.pdf\n').encode()
        if target:target.write(data);return b''
        raise AssertionError('Unexpected download')
    return fetch


class ArchiveTests(unittest.TestCase):
    def test_checksum_rejects_missing_ambiguous_or_malformed_detector_records(self):
        line=('  '+'a'*32+' snort-openappid.tar.gz').encode()
        for value in (b'\xff',line+b'.old',line+b'\n'+line,b'a'*31+b' snort-openappid.tar.gz'):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'格式无效'):
                u.detector_md5(value)

    def test_rejects_traversal_links_devices_duplicates_and_oversized_members(self):
        for members in ([('../escaped',b'',None)], [('/absolute',b'',None)],
                        [('odp/back\\slash',b'',None)], [('odp/link',b'',tarfile.SYMTYPE)],
                        [('odp/link',b'',tarfile.LNKTYPE)], [('odp/device',b'',tarfile.CHRTYPE)],
                        [('odp/repeat',b'a',None),('odp/repeat',b'b',None)]):
            with self.subTest(members=members),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path=root/'archive.tar.gz';path.write_bytes(archive(members));dest=root/'out';dest.mkdir()
                with self.assertRaises(ValueError):u.extract(path,dest)
                self.assertFalse((root/'escaped').exists())

    def test_update_skip_and_pointer_restore_keep_custom_detectors(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);previous=existing(root);saved=u.snapshot(root)
            custom=root/'custom/lua';custom.mkdir(parents=True);(custom/'local.lua').write_text('preserve')
            data=archive();lines=[]
            with mock.patch.object(u,'fetch',side_effect=downloader(data)):
                self.assertTrue(u.update(lines,root));current=(root/'odp').resolve()
                self.assertNotEqual(current,previous);self.assertTrue((current/'lua/http.lua').is_file())
                self.assertFalse(u.update(lines,root))
            self.assertEqual((custom/'local.lua').read_text(),'preserve')
            u.restore(saved,root);self.assertEqual((root/'odp').resolve(),previous)
            self.assertFalse((root/'update.json').exists())

    def test_checksum_failure_never_switches_detectors(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);previous=existing(root);fetch=downloader(archive())
            def tampered(url,target=None,maximum=None):
                if target:target.write(b'tampered');return b''
                return fetch(url,target,maximum)
            with mock.patch.object(u,'fetch',side_effect=tampered),self.assertRaisesRegex(ValueError,'校验'):
                u.update([],root)
            self.assertEqual((root/'odp').resolve(),previous)
            self.assertFalse(any((root/'releases').glob('.download-*')))

    def test_downloads_accept_only_https_official_origins_and_do_not_leak_urls(self):
        for url in ('http://www.snort.org/a','https://evil.example/a','https://www.snort.org@evil.example/',
                    'https://www.snort.org:444/a','file:///etc/passwd'):
            self.assertFalse(u._allowed(url))
        with mock.patch.object(u.urllib.request,'build_opener',side_effect=RuntimeError('https://private.example/?secret=abc')):
            with self.assertRaisesRegex(RuntimeError,'官方下载失败') as caught:u.fetch(u.PAGE)
        self.assertNotIn('secret',str(caught.exception))


class JobTests(unittest.TestCase):
    setUp=fixture.ManagerCase.setUp
    wait=fixture.ManagerCase.wait
    def test_scheduled_update_reloads_openappid_and_failure_restores_the_directory(self):
        root=self.base/'appid';previous=existing(root);self.module.APPID_ROOT=str(root)
        data=archive();calls=[]
        def engine(commands,timeout=300):
            calls.extend(commands)
            if commands==['appid-reload-detectors'] and len(calls)==1:
                self.assertNotEqual((root/'odp').resolve(),previous)
                return {'__error__':'synthetic detector reload failure'}
            return {commands[0]:{}}
        with mock.patch.object(u,'fetch',side_effect=downloader(data)),mock.patch.object(self.jobs,'run'), \
                mock.patch.object(self.jobs.local.engine,'call',side_effect=engine):
            self.assertTrue(self.jobs.update_rules(trigger='schedule')['ok']);self.assertEqual(self.wait()['rc'],1)
        self.assertEqual((root/'odp').resolve(),previous)
        self.assertEqual(calls,['appid-reload-detectors','appid-reload-detectors','ruleset-reload-rules'])
        self.assertFalse((root/'update.json').exists())

    def test_interrupted_uncommitted_journal_restores_the_openappid_pointer(self):
        root=self.base/'appid';previous=existing(root);self.module.APPID_ROOT=str(root)
        import ips_control
        backup=ips_control.RuleBackup(self.module,self.manager.state);backup.mark_detector_reload()
        with mock.patch.object(u,'fetch',side_effect=downloader(archive())):u.update([],root)
        recovered=ips_control.RuleBackup.load(backup.directory,self.module);recovered.restore();recovered.close()
        self.assertEqual((root/'odp').resolve(),previous)


if __name__=='__main__':unittest.main()
