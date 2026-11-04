"""Covered bind mounts cannot silently redirect resets to another filesystem."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import log_storage as storage


class LogPathTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.persistent=self.root/'persistent';self.marker=self.root/'marker.json'
        self.native=self.root/'visible-native';self.events=self.root/'visible-events'
        for path in (self.persistent/'snort',self.persistent/'events',self.native,self.events):path.mkdir(parents=True)
        self.marker.write_text(json.dumps(dict(root=str(self.persistent))))
        patch=mock.patch.multiple(storage,ROOT=self.persistent,MARKER=self.marker,
                                  BINDINGS=((self.native,'snort'),(self.events,'events')))
        patch.start();self.addCleanup(patch.stop)
        env=mock.patch.dict(os.environ,{},clear=True);env.start();self.addCleanup(env.stop)

    def test_same_filesystem_but_different_directory_is_rejected(self):
        self.assertEqual(self.native.stat().st_dev,(self.persistent/'snort').stat().st_dev)
        with self.assertRaisesRegex(RuntimeError,'挂载被遮盖'):storage.validate_log_storage()

    def test_direct_paths_ignore_covered_aliases_and_keep_native_stream_consistent(self):
        self.marker.write_text(json.dumps(dict(root=str(self.persistent),direct_paths=True)))
        storage.validate_log_storage()
        self.assertEqual(storage.log_paths(),(self.persistent/'snort',self.persistent/'events/events.json'))

    def test_private_marker_does_not_prevent_sandboxed_web_from_using_service_paths(self):
        with mock.patch.object(Path,'read_text',side_effect=PermissionError), \
             mock.patch.dict(os.environ,{'IPS_LOG_STORAGE_ROOT':str(self.persistent)}):
            self.assertEqual(storage.log_paths()[1],self.persistent/'events/events.json')

    def test_unknown_root_and_missing_direct_directory_are_rejected(self):
        self.marker.write_text(json.dumps(dict(root=str(self.root/'unmanaged'))))
        with self.assertRaises(RuntimeError):storage.log_paths()
        self.marker.write_text(json.dumps(dict(root=str(self.persistent),direct_paths=True)))
        (self.persistent/'events').rmdir()
        with self.assertRaises(RuntimeError):storage.validate_log_storage()


if __name__=='__main__':unittest.main()
