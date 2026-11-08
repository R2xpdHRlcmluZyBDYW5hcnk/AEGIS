"""Prevent host/target and matching-library mixups in engine build artifacts."""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from build_tools.engine_platform import architecture,elf_architecture,matcher,runner,sources_for

ROOT=Path(__file__).resolve().parents[1]


class EnginePlatformTests(unittest.TestCase):
    def test_matching_sources_are_isolated_without_changing_input(self):
        original=json.loads((ROOT/'build_tools/snort-sources.json').read_text())
        for alias,arch,selected,excluded in [('arm64','aarch64','vectorscan','hyperscan'),
                                            ('amd64','x86_64','hyperscan','vectorscan')]:
            with self.subTest(arch=arch):
                resolved=sources_for(original,alias)
                self.assertEqual(resolved['target']['architecture'],arch)
                self.assertEqual(matcher(alias),selected)
                self.assertIn(selected,resolved)
                self.assertNotIn(excluded,resolved)
                resolved['snort']['version']='changed'
                self.assertNotEqual(resolved['snort']['version'],original['snort']['version'])
        self.assertIn('hyperscan',original)
        self.assertIn('vectorscan',original)
        self.assertEqual(original['target']['architecture'],'aarch64')

    def test_binary_headers_determine_target_instead_of_host_or_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'snort'
            for machine,expected in [(62,'x86_64'),(183,'aarch64')]:
                header=bytearray(20);header[:6]=b'\x7fELF\x02\x01';header[18:20]=machine.to_bytes(2,'little')
                binary.write_bytes(header)
                self.assertEqual(elf_architecture(binary),expected)
            for value in [b'invalid',b'\x7fELF\x01\x01'+bytes(14),b'\x7fELF\x02\x01'+bytes(14)]:
                binary.write_bytes(value)
                with self.assertRaises(ValueError):elf_architecture(binary)

    def test_native_x86_runs_directly_and_arm_cross_validation_uses_qemu(self):
        with mock.patch('build_tools.engine_platform.platform.machine',return_value='x86_64'):
            self.assertEqual(runner('amd64'),[])
            self.assertEqual(runner('arm64'),['qemu-aarch64'])
        with mock.patch('build_tools.engine_platform.platform.machine',return_value='aarch64'):
            self.assertEqual(runner('aarch64'),[])
            with self.assertRaisesRegex(ValueError,'x86-64 host'):runner('x86_64')
        with self.assertRaises(ValueError):architecture('i386')

    def test_session_builder_rejects_mismatched_sdk_before_building(self):
        from build_tools import build_session_logger as builder
        spec=json.loads((ROOT/'build_tools/snort-sources.json').read_text())['snort']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'snort';output=root/'output'
            header=bytearray(20);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(62).to_bytes(2,'little');binary.write_bytes(header)
            valid=dict(architecture='x86_64',sha256=hashlib.sha256(header).hexdigest(),
                sources={'snort':spec},session_patch=builder.REVISION)
            for key,value in [('architecture','aarch64'),('sha256','changed'),
                              ('sources',{'snort':{}}),('session_patch','old')]:
                (root/'engine-manifest.json').write_text(json.dumps(dict(valid,**{key:value})))
                with self.subTest(field=key),mock.patch.object(builder.shutil,'which') as compiler, \
                        mock.patch.object(builder.urllib.request,'urlopen') as download:
                    with self.assertRaisesRegex(ValueError,'Engine and SDK'):
                        builder.build(output,binary,prefix=str(root))
                    compiler.assert_not_called();download.assert_not_called()
                    self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
