"""Retired cleanup must never traverse the current Snort installation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class LegacyCleanupCase(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('legacy_cleanup',ROOT/'cleanup-legacy-suricata.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_current_directory_and_ancestors_cannot_be_deleted(self):
        current=self.root/'current';current.mkdir();(current/'database').write_bytes(b'protected')
        for target in (current,self.root,current/'database'):
            with self.assertRaisesRegex(ValueError,'overlaps'):
                self.module.remove(target,[current.resolve()])
        self.assertEqual((current/'database').read_bytes(),b'protected')

    def test_retired_database_is_removed_without_touching_native_database(self):
        current=self.root/'ips-snort-web';current.mkdir();(current/'events.db').write_bytes(b'new database')
        old=self.root/'ips-web';old.mkdir();(old/'events.db').write_bytes(b'old database')
        self.module.remove(old,[current.resolve()])
        self.assertFalse(old.exists());self.assertEqual((current/'events.db').read_bytes(),b'new database')

    def test_backup_ownership_uses_recorded_layout_instead_of_name(self):
        old=self.root/'old';new=self.root/'new';old.mkdir();new.mkdir()
        (old/'state.before.json').write_text(json.dumps(dict(files={'/etc/ips-web.conf':'fixture'})))
        (new/'state.before.json').write_text(json.dumps(dict(files={'/etc/snort/snort.lua':'fixture','/opt/ips-console/bin/ips-web':'fixture'})))
        self.assertTrue(self.module.legacy_backup(old));self.assertFalse(self.module.legacy_backup(new))


if __name__=='__main__':unittest.main()
