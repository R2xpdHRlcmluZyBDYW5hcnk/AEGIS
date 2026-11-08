"""Synthetic migration failure, rollback, file preservation and clear boundaries."""
import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import shutil
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]


def load():
    spec=importlib.util.spec_from_file_location('log_storage_deploy',ROOT/'deploy-log-storage.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class LogStorageCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.module=load()

    def test_verified_copy_rejects_links_and_preserves_data(self):
        source=self.root/'source';source.mkdir();(source/'events.json').write_bytes(b'fixture\n')
        target=self.root/'target'
        self.module.copy_verified(source,target)
        self.assertEqual((target/'events.json').read_bytes(),b'fixture\n')
        with mock.patch.object(Path,'is_symlink',return_value=True):
            with self.assertRaisesRegex(ValueError,'Unsupported log entry'):self.module.inventory(source)

    def exercise_migration(self,fail=False,clear_logs=False):
        m=self.module;root=self.root
        logs=(root/'ram/snort',root/'ram/ips')
        for path in logs:path.mkdir(parents=True)
        (logs[0]/'0_file_connector_ndr_transmit').write_text('native fixture\n')
        (logs[1]/'events.json').write_text('events fixture\n')
        event=(logs[1]/'events.json').stat()
        value=dict(device=event.st_dev,inode=event.st_ino,offset=4)
        db=root/'events.db'
        with closing(sqlite3.connect(db)) as conn,conn:
            conn.executescript('CREATE TABLE event_state(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE events(data TEXT); INSERT INTO events VALUES("protected");')
            conn.execute('INSERT INTO event_state VALUES(?,?)',('stream_cutoff',json.dumps(value)))
        config=root/'config.json';config.write_text(json.dumps(dict(event_db=str(db),port=9000)))
        units=root/'units';units.mkdir();rotation=root/'rotation';rotation.write_text('old rotation\n')
        backups=root/'backups';persistent=root/'disk';marker=root/'marker.json'
        mounted=set()
        def run(*args):
            if args[0]=='findmnt':return 'ext4\n'
            if args[:2]==('systemctl','start'):
                mounted.update(args[2:])
            if args[:2]==('systemctl','stop'):
                mounted.difference_update(args[2:])
            return ''
        def ismount(path):return ('var-log-'+Path(path).name+'.mount') in mounted
        client=mock.Mock();client.request.return_value={'ok':True}
        healthy=mock.Mock(side_effect=[RuntimeError('synthetic health failure'),None] if fail else None)
        with mock.patch.multiple(m,ROOT=persistent,BACKUPS=backups,MARKER=marker,UNIT_ROOT=units,LOGS=logs,ROTATION=rotation), \
             mock.patch.object(m,'Client',return_value=client),mock.patch.object(m,'layout',return_value={'config':str(config)}), \
             mock.patch.object(m,'run',side_effect=run),mock.patch.object(m.os.path,'ismount',side_effect=ismount), \
             mock.patch.object(m,'stop_services'),mock.patch.object(m,'resume'),mock.patch.object(m,'healthy',healthy), \
             mock.patch.object(m.subprocess,'run',return_value=mock.Mock(returncode=0)):
            if fail:
                with self.assertRaisesRegex(RuntimeError,'synthetic health failure'):m.apply(ROOT)
                self.assertFalse(marker.exists())
            else:
                m.apply(ROOT)
                self.assertTrue(marker.exists())
                self.assertFalse(any(root.glob('ram/.*-ips-before-*')))
                current=json.loads(m.cutoff(db)['value'])
                self.assertEqual(current['offset'],4)
                self.assertEqual(current['inode'],(persistent/'events/events.json').stat().st_ino)
                (persistent/'snort/new.log').write_text('post-migration data')
                if clear_logs:
                    import shutil
                    backup=next(backups.iterdir());state_path=backup/'state.json'
                    state=json.loads(state_path.read_text());state['logs_removed']=True;state_path.write_text(json.dumps(state))
                    for name in ('logs-snort','logs-ips'):shutil.rmtree(backup/name)
                m.rollback(next(backups.iterdir()))
                self.assertEqual((persistent/'snort/new.log').read_text(),'post-migration data')
            if clear_logs:
                self.assertFalse(list(logs[0].iterdir()));self.assertFalse(list(logs[1].iterdir()))
            else:
                self.assertEqual((logs[0]/'0_file_connector_ndr_transmit').read_text(),'native fixture\n')
                self.assertEqual((logs[1]/'events.json').read_text(),'events fixture\n')
            self.assertEqual(rotation.read_text(),'old rotation\n')
            current=json.loads(m.cutoff(db)['value'])
            if clear_logs:self.assertIsNone(current)
            else:
                self.assertEqual(current['offset'],4)
                self.assertEqual(current['inode'],(logs[1]/'events.json').stat().st_ino)
            with closing(sqlite3.connect(db)) as conn:self.assertEqual(conn.execute('SELECT * FROM events').fetchall(),[('protected',)])

    def test_failed_migration_restores_originals_and_preserves_database(self):self.exercise_migration(True)
    def test_completed_migration_rollback_retains_new_disk_logs(self):self.exercise_migration()
    def test_configuration_rollback_still_works_after_raw_snapshots_are_deleted(self):self.exercise_migration(clear_logs=True)

    def test_clear_cutoff_only_translates_the_matching_file(self):
        old=self.root/'old';new=self.root/'new';old.write_text('fixture');new.write_text('fixture')
        info=old.stat();other=dict(device=info.st_dev,inode=info.st_ino+1,offset=2)
        self.assertEqual(self.module.translate_cutoff(other,info,new.stat()),other)
        with self.assertRaisesRegex(ValueError,'boundary'):
            self.module.translate_cutoff(dict(device=info.st_dev,inode=info.st_ino,offset=100),info,new.stat())

    def test_draining_waits_for_complete_lines_and_preserves_a_torn_final_line(self):
        path=self.root/'native';path.write_bytes(b'complete\npartial')
        state={path.name:dict(inode=path.stat().st_ino,offset=0)}
        self.assertFalse(self.module.bridge_drained([path],state))
        state[path.name]['offset']=len(b'complete\n')
        self.assertTrue(self.module.bridge_drained([path],state))


    def exercise_direct_repair(self,failure=False):
        m=self.module;root=self.root
        logs=(root/'visible/snort',root/'visible/ips');persistent=root/'persistent'
        for path in (*logs,persistent/'snort',persistent/'events'):path.mkdir(parents=True)
        raw=logs[0]/'0_file_connector_ndr_transmit';raw.write_text('visible native evidence\n')
        stream=logs[1]/'events.json';stream.write_text('visible event evidence\n');identity=stream.stat()
        (persistent/'snort/old-native').write_text('covered native evidence\n')
        (persistent/'events/events.json').write_text('covered event evidence\n')
        programs=('ips-web','ips-supervisor','deployment_support.py');installed=root/'programs';installed.mkdir()
        release=root/'release';release.mkdir();(release/'logrotate-snort').write_bytes((ROOT/'logrotate-snort').read_bytes())
        for name in ('deploy-log-storage.py','deployment_layout.py','deploy-backend.py',*m.MOUNTS):(release/name).write_bytes((ROOT/name).read_bytes())
        for name in programs:
            (installed/name).write_text('# previous program\n');(release/name).write_bytes(b'# helper\n' if name.endswith('.py') else b'\x7fELF'+bytes(60))
        db=root/'events.db';boundary=dict(device=identity.st_dev,inode=identity.st_ino,offset=5)
        with closing(sqlite3.connect(db)) as conn,conn:
            conn.executescript('CREATE TABLE event_state(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE events(data TEXT); INSERT INTO events VALUES("protected");')
            conn.execute('INSERT INTO event_state VALUES(?,?)',('stream_cutoff',json.dumps(boundary)))
        config=root/'config';original=json.dumps(dict(event_db=str(db),eve=str(stream),password_pbkdf2='fixture-hash'))
        config.write_text(original);marker=root/'marker';marker.write_text(json.dumps(dict(root=str(persistent))))
        units=root/'units';units.mkdir();rotation=root/'rotation';rotation.write_text('previous rotation\n')
        backups=root/'backups';calls=[];checkpoint=root/'checkpoint.json'
        checkpoint.write_text('{"epoch":"fixture","files":{}}')
        def run(*args):
            calls.append(args)
            return 'ext4\n' if args[0]=='findmnt' else ''
        healthy=mock.Mock(side_effect=[RuntimeError('candidate unhealthy'),None] if failure else None)
        client=mock.Mock();client.request.return_value={'ok':True}
        with mock.patch.multiple(m,ROOT=persistent,BACKUPS=backups,MARKER=marker,UNIT_ROOT=units,LOGS=logs,ROTATION=rotation,CHECKPOINT=checkpoint), \
             mock.patch.object(m,'Client',return_value=client),mock.patch.object(m,'run',side_effect=run), \
             mock.patch.object(m,'repair_programs',return_value=programs), \
             mock.patch.object(m,'layout',return_value=dict(program_dir=str(installed),config=str(config))), \
             mock.patch.object(m,'stop_services',return_value={'epoch':'fixture','started':0}), \
             mock.patch.object(m,'drain_preserved_logs'),mock.patch.object(m,'resume'),mock.patch.object(m,'healthy',healthy), \
             mock.patch.object(m.subprocess,'run',return_value=mock.Mock(returncode=0)):
            if failure:
                with self.assertRaisesRegex(RuntimeError,'candidate unhealthy'):m.apply_direct(release)
            else:
                m.apply_direct(release)
                self.assertTrue(json.loads(marker.read_text())['direct_paths'])
                self.assertEqual((persistent/'events/events.json').read_text(),stream.read_text())
                self.assertEqual(json.loads(m.cutoff(db)['value'])['inode'],(persistent/'events/events.json').stat().st_ino)
                self.assertIn(str(persistent/'snort'),rotation.read_text())
                self.assertNotIn('/var/log/snort/',rotation.read_text())
                (persistent/'snort/new-native').write_text('new evidence\n')
                backup=next(backups.iterdir())
                self.assertEqual((backup/'persistent-before-snort/old-native').read_text(),'covered native evidence\n')
                m.rollback(backup)
                self.assertEqual((backup/'failed-generated-snort/new-native').read_text(),'new evidence\n')
            self.assertEqual(raw.read_text(),'visible native evidence\n')
            self.assertEqual(stream.read_text(),'visible event evidence\n')
            self.assertEqual((persistent/'snort/old-native').read_text(),'covered native evidence\n')
            self.assertEqual(config.read_text(),original)
            self.assertEqual(rotation.read_text(),'previous rotation\n')
            self.assertFalse(json.loads(marker.read_text()).get('direct_paths'))
            self.assertEqual(json.loads(m.cutoff(db)['value']),boundary)
            for name in programs:self.assertEqual((installed/name).read_text(),'# previous program\n')
            with closing(sqlite3.connect(db)) as conn:self.assertEqual(conn.execute('SELECT * FROM events').fetchall(),[('protected',)])

    def test_direct_repair_preserves_visible_covered_and_new_logs_during_rollback(self):
        self.exercise_direct_repair()

    def test_direct_repair_health_failure_restores_programs_authentication_and_read_boundary(self):
        self.exercise_direct_repair(failure=True)



if __name__=='__main__':unittest.main()
