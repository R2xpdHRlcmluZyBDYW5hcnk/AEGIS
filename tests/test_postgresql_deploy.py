"""Repository trust and PostgreSQL activation must fail before unsafe mutations."""
import importlib.util
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('postgresql_deployer',ROOT/'deploy-postgresql.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class PostgreSQLDeploymentTests(unittest.TestCase):
    def test_postgresql_snapshot_does_not_require_retired_sqlite(self):
        loader=importlib.util.spec_from_file_location('postgresql_static_deployer',ROOT/'deploy-angular.py')
        static=importlib.util.module_from_spec(loader)
        # fcntl is only used when the target-side deployer is invoked on Linux.
        import sys,types
        with mock.patch.dict(sys.modules,{'fcntl':types.ModuleType('fcntl')}):loader.loader.exec_module(static)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'retired.db'
            cfg=dict(event_db=str(path),database_url=module.DATABASE_URL)
            with mock.patch.object(static.subprocess,'check_output',return_value='123:456:789\n') as query:
                self.assertEqual(static.database_snapshot(cfg),dict(db_inode=None,postgres_identity='123:456:789'))
                self.assertIn('pg_control_system()',query.call_args.args[0][-1])
            with self.assertRaises(FileNotFoundError):static.database_snapshot(dict(event_db=str(path)))
            with mock.patch.object(static.subprocess,'check_output') as query:
                with self.assertRaisesRegex(ValueError,'endpoint'):
                    static.database_snapshot(dict(event_db=str(path),database_url='postgresql://aegis_web@invalid/aegis'))
                query.assert_not_called()

    def test_deployment_health_waits_for_ingestion(self):
        from tests.test_deploy_backend import deployer
        opener=mock.Mock()
        opener.open.side_effect=[io.BytesIO(b'{"ok":true,"event_db_ready":false}'),io.BytesIO(b'{"ok":true,"event_db_ready":true}')]
        with mock.patch.object(deployer.urllib.request,'build_opener',return_value=opener),mock.patch.object(deployer.time,'sleep'):
            self.assertTrue(deployer.wait_ready({})['event_db_ready'])
        self.assertEqual(opener.open.call_count,2)

    def test_dynamic_user_must_be_resolvable_before_configuring_peer_authentication(self):
        with mock.patch.object(module.subprocess,'run',return_value=mock.Mock(returncode=2,stdout='')):
            with self.assertRaisesRegex(RuntimeError,'DynamicUser cannot be resolved'):
                module.verify_console_identity('ips-web')
        with mock.patch.object(module.subprocess,'run',return_value=mock.Mock(returncode=0,stdout='ips-web:x:60001:60001:fixture:/:/usr/sbin/nologin\n')):
            module.verify_console_identity('ips-web')
        self.assertIn("'libnss-systemd'",(ROOT/'deploy-postgresql.py').read_text())

    def test_storage_switch_restarts_only_console_and_restores_configuration_on_failure(self):
        from tests.test_go_backend import deployer,native_fixture
        for failure in (False,True):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                native=deployer();root=Path(temporary);release=root/'release';installed=root/'installed'
                release.mkdir();installed.mkdir()
                for name in native.PROGRAMS:
                    (release/name).write_text('# candidate helper\n');(installed/name).write_text('# previous helper\n')
                manifest=native_fixture(release,native)
                config=root/'config';original={'password_pbkdf2':'fixture','preload_memory_mib':512};config.write_text(json.dumps(original))
                client=mock.Mock();client.request.return_value={'ok':True,'ready':True}
                health=dict(backend='go',go_version='go1.27.3',sqlite_version='3.54.1',event_database='postgresql',event_db_ready=True,wal_compression='zstd',timescaledb_version='2.31.0')
                ready=mock.Mock(side_effect=[RuntimeError('fixture activation failure'),{}] if failure else [health])
                with mock.patch.multiple(native,CONFIG=config,BIN=installed,BACKUPS=root/'backups',SIGNATURE_SOURCES=root/'signature-sources.json',PIDFILE=root/'pid',RESOURCE_ROOT=root/'units'),mock.patch.object(native,'validate_go_manifest',return_value=manifest),mock.patch.object(native,'Client',return_value=client),mock.patch.object(native.subprocess,'run',return_value=mock.Mock(returncode=0)) as run,mock.patch.object(native.subprocess,'check_output',return_value='{"archive":"aegis_history_aaaaaaaaaaaaaaaa"}') as command,mock.patch('builtins.print'):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError,'fixture activation failure'):
                            native.apply(release,ready,{'database_url':module.DATABASE_URL},reset_event_data=True)
                    else:native.apply(release,ready,{'database_url':module.DATABASE_URL},reset_event_data=True)
                updated=json.loads(config.read_text())
                self.assertEqual({k:updated[k] for k in original},original)
                self.assertEqual('database_url' in updated,not failure)
                self.assertEqual(command.call_args.args[0][1],'postgresql-reset')
                service_calls=[call.args[0] for call in run.call_args_list if call.args[0][:2] in (['systemctl','stop'],['systemctl','start'])]
                self.assertTrue(service_calls)
                self.assertTrue(all(call[2:]==['ips-web'] for call in service_calls))

    def test_signing_keys_are_fetched_and_primary_fingerprints_are_checked(self):
        repository={'name':'fixture','keyUrl':'https://example.org/key','primaryFingerprints':['A'*40,'B'*40]}
        response=mock.MagicMock();response.__enter__.return_value.read.return_value=b'public-key-fixture'
        result=mock.Mock(stdout=('pub:::::::::\nfpr:::::::::'+'B'*40+':\nsub:::::::::\nfpr:::::::::'+'C'*40+':\n').encode())
        with mock.patch.object(module.urllib.request,'urlopen',return_value=response),mock.patch.object(module.subprocess,'run',return_value=result):
            self.assertEqual(module.verified_repository_key(repository),b'public-key-fixture')
            repository['primaryFingerprints']=['A'*40]
            with self.assertRaisesRegex(ValueError,'Unrecognized'):
                module.verified_repository_key(repository)

    def test_all_keys_are_validated_before_repository_files_are_written(self):
        source={'repositories':[{'name':'first'},{'name':'second'}]}
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(module,'verified_repository_key',side_effect=[b'first',ValueError('rotation')]):
            with self.assertRaises(ValueError):module.repository_files(source,temporary,'arm64')
            self.assertEqual(list(Path(temporary).iterdir()),[])

    def test_release_sources_contain_no_public_key_material(self):
        package_spec=importlib.util.spec_from_file_location('postgresql_release_package',ROOT/'package.py')
        package=importlib.util.module_from_spec(package_spec);package_spec.loader.exec_module(package)
        self.assertIn('deploy-postgresql.py',package.FILES)
        self.assertTrue(all(Path(name).suffix not in ('.asc','.gpg','.keyring') for name in package.FILES))
        sources=json.loads(module.SOURCES.read_text())
        self.assertTrue(all(repo['keyUrl'].startswith('https://') and repo['primaryFingerprints'] for repo in sources['repositories']))
        for path in [ROOT/'deploy-postgresql.py',module.SOURCES]:
            self.assertNotIn('-----BEGIN PGP PUBLIC KEY BLOCK-----',path.read_text())

    def test_durable_settings_and_loopback_only_access_are_explicit(self):
        text=(ROOT/'deploy-postgresql.py').read_text()
        for setting in ("listen_addresses = ''","wal_compression = 'zstd'",'synchronous_commit = on','fsync = on','full_page_writes = on'):
            self.assertIn(setting,text)
        self.assertIn('local all all reject',text)
        self.assertIn("if not limits.exists()",text)
