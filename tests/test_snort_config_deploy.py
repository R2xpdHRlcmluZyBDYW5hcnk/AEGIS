"""A configuration update must validate first and restore runtime on failure."""
from contextlib import contextmanager, ExitStack
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('snort_config_deployer', ROOT/'deploy-snort-config.py')
deploy = importlib.util.module_from_spec(spec); spec.loader.exec_module(deploy)


class SnortConfigDeploymentTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory); release = root/'release'; release.mkdir()
            config = root/'snort.lua'; config.write_bytes(b'old configuration\n')
            home = root/'home-net.lua'; home.write_bytes(b'HOME_NET="any"\n')
            (release/'snort.lua').write_bytes(b'new configuration\n')
            client = mock.Mock(); client.request.return_value = {'ok':True}
            stack.enter_context(mock.patch.multiple(deploy, CONFIG=config, BACKUPS=root/'backups'))
            stack.enter_context(mock.patch.object(deploy.os, 'geteuid', return_value=0, create=True))
            stack.enter_context(mock.patch.object(deploy, 'Client', return_value=client))
            process = stack.enter_context(mock.patch.object(deploy.session_logger, 'process_key', return_value=[7,'8','fixture']))
            stack.enter_context(mock.patch.object(deploy.session_logger, 'plugin_arguments', return_value=['--plugin-path','/test/ndr_session.so']))
            run = stack.enter_context(mock.patch.object(deploy.subprocess, 'run', return_value=mock.Mock(returncode=0,stdout=b'validation fixture')))
            reload = stack.enter_context(mock.patch.object(deploy, 'reload_config'))
            stack.enter_context(mock.patch('sys.stdout', new=io.StringIO()))
            yield root, release, config, client, run, reload, process
            self.assertEqual(home.read_bytes(), b'HOME_NET="any"\n')

    def test_non_root_cannot_pause_or_modify_configuration(self):
        with mock.patch.object(deploy.os,'geteuid',return_value=1000,create=True), mock.patch.object(deploy,'Client') as client:
            with self.assertRaises(PermissionError):deploy.deploy(ROOT)
        client.assert_not_called()

    def test_busy_manager_leaves_configuration_untouched(self):
        with self.fixture() as (root, release, config, client, run, reload, process):
            client.request.return_value={'ok':False}
            with self.assertRaisesRegex(RuntimeError,'busy'):deploy.deploy(release)
            self.assertEqual(config.read_bytes(),b'old configuration\n')
            run.assert_not_called();reload.assert_not_called()
            self.assertFalse((root/'backups').exists())

    def test_validation_failure_keeps_original_file_and_runtime(self):
        with self.fixture() as (root, release, config, client, run, reload, process):
            run.return_value.returncode=1
            with self.assertRaisesRegex(RuntimeError,'validation failed'):deploy.deploy(release)
            self.assertEqual(config.read_bytes(),b'old configuration\n')
            reload.assert_not_called()
            self.assertEqual(client.request.call_args,mock.call('maintenance',enabled=False))
            self.assertEqual(next((root/'backups').glob('*/snort.lua.before')).read_bytes(),config.read_bytes())

    def test_success_validates_matching_plugin_and_never_restarts_a_service(self):
        with self.fixture() as (root, release, config, client, run, reload, process):
            deploy.deploy(release)
            self.assertEqual(config.read_bytes(),(release/'snort.lua').read_bytes())
            self.assertEqual(run.call_count,1)
            command=run.call_args.args[0]
            self.assertEqual(command[:4],[deploy.BINARY,'--plugin-path','/test/ndr_session.so','-T'])
            reload.assert_called_once()
            self.assertEqual(process.call_count,3)
            self.assertTrue(next((root/'backups').glob('*/verification.json')).is_file())
            self.assertEqual(client.request.call_args,mock.call('maintenance',enabled=False))

    def test_reload_failure_restores_file_and_reloads_original(self):
        with self.fixture() as (root, release, config, client, run, reload, process):
            seen=[]
            def attempt(control):
                seen.append(config.read_bytes())
                if len(seen)==1:raise RuntimeError('synthetic reload failure')
            reload.side_effect=attempt
            with self.assertRaisesRegex(RuntimeError,'synthetic reload failure'):deploy.deploy(release)
            self.assertEqual(seen,[b'new configuration\n',b'old configuration\n'])
            self.assertEqual(config.read_bytes(),b'old configuration\n')
            self.assertEqual(client.request.call_args,mock.call('maintenance',enabled=False))

    def test_failed_runtime_rollback_is_reported_and_backup_retained(self):
        with self.fixture() as (root, release, config, client, run, reload, process):
            reload.side_effect=RuntimeError('control unavailable')
            with self.assertRaisesRegex(RuntimeError,'runtime rollback failed'):deploy.deploy(release)
            self.assertEqual(config.read_bytes(),b'old configuration\n')
            self.assertEqual(reload.call_count,2)
            self.assertTrue(next((root/'backups').glob('*/snort.lua.before')).is_file())

    def test_uncoordinated_config_change_during_validation_is_not_overwritten(self):
        with self.fixture() as (root, release, config, client, run, reload, process):
            def validate(*args,**kwargs):
                config.write_bytes(b'administrator change\n')
                return mock.Mock(returncode=0,stdout=b'valid')
            run.side_effect=validate
            with self.assertRaisesRegex(RuntimeError,'update cancelled'):deploy.deploy(release)
            self.assertEqual(config.read_bytes(),b'administrator change\n')
            reload.assert_not_called()

    def test_reload_without_extension_waits_for_new_generation(self):
        control=mock.Mock();control.command.side_effect=['generation 1','accepted','generation 2']
        with mock.patch.object(deploy.session_logger,'plugin_arguments',return_value=[]):
            deploy.reload_config(control)
        self.assertEqual(control.command.call_count,3)
        self.assertTrue(control.command.call_args_list[1].args[0].startswith('snort.reload_config('))

    def test_reload_reuses_installed_extension_transaction(self):
        control=mock.Mock()
        with mock.patch.object(deploy.session_logger,'plugin_arguments',return_value=['--plugin-path','/test/ndr_session.so']), \
                mock.patch.object(deploy.session_logger,'reload_extension') as reload:
            deploy.reload_config(control)
        reload.assert_called_once_with(control,deploy.CONFIG)
        control.command.assert_not_called()


if __name__ == '__main__':unittest.main()
