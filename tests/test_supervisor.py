"""NFQUEUE watchdog timing, restart coordination and supervisor deployment."""
from contextlib import nullcontext
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


supervisor = load('detector_supervisor', ROOT / 'ips-supervisor')
deploy = load('supervisor_deployer', ROOT / 'deploy-supervisor.py')
ALL = supervisor.QUEUE_IDS
WITHOUT_0 = ALL - {'0'}


class QueueWatchdogCase(unittest.TestCase):
    def test_snapshot_distinguishes_missing_listeners_from_unreadable_state(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'nfnetlink_queue'
            with mock.patch.object(supervisor, 'NFQ_PROC', path):
                self.assertIsNone(supervisor.queue_listeners())
                path.write_text('')
                self.assertEqual(supervisor.queue_listeners(), set())
                path.write_text('  0  1209  0\n  1  0  0\n  9  100  0\n')
                self.assertEqual(supervisor.queue_listeners(), {'0'})
                path.write_text('0 1209\n1 incomplete\n')
                self.assertIsNone(supervisor.queue_listeners())

    def test_normal_reload_transient_loss_and_uncertain_sample(self):
        health = supervisor.QueueHealth(0)
        self.assertFalse(health.overdue(ALL, 1))
        self.assertFalse(health.overdue(WITHOUT_0, 2))
        self.assertFalse(health.overdue(WITHOUT_0, 16))
        self.assertFalse(health.overdue(ALL, 17))
        self.assertFalse(health.overdue(WITHOUT_0, 18))
        self.assertFalse(health.overdue(None, 28))
        self.assertFalse(health.overdue(WITHOUT_0, 35))
        self.assertEqual(health.overdue(WITHOUT_0, 50), {'0'})

    def test_startup_grace_and_separate_timing_per_queue(self):
        health = supervisor.QueueHealth(0)
        self.assertFalse(health.overdue(WITHOUT_0, 119))
        self.assertFalse(health.overdue(WITHOUT_0, 120))
        self.assertFalse(health.overdue(WITHOUT_0 - {'2'}, 133))
        self.assertEqual(health.overdue(WITHOUT_0 - {'2'}, 135), {'0'})
        self.assertFalse(health.overdue(ALL - {'2'}, 136))
        self.assertEqual(health.overdue(ALL - {'2'}, 148), {'2'})

    def test_restart_defers_for_configuration_work_and_rechecks_queue(self):
        snort = mock.Mock()
        with mock.patch('snort_engine.configuration_lock', side_effect=BlockingIOError):
            self.assertFalse(supervisor.recover_snort(snort, threading.Event(), {'0'}, False))
        with (mock.patch('snort_engine.configuration_lock', return_value=nullcontext()),
              mock.patch.object(supervisor, 'queue_listeners', return_value=ALL)):
            self.assertFalse(supervisor.recover_snort(snort, threading.Event(), {'0'}, False))
        snort.stop.assert_not_called()

    def test_confirmed_loss_stops_only_the_detector_and_verifies_recovery(self):
        snort = mock.Mock()
        snort.alive.return_value = False
        stop = threading.Event()
        with (mock.patch('snort_engine.configuration_lock', return_value=nullcontext()) as lock,
              mock.patch.object(supervisor, 'queue_listeners', return_value=WITHOUT_0),
              mock.patch.object(supervisor, 'start_snort', return_value=True) as start,
              mock.patch.object(supervisor, 'wait_snort_ready', return_value=True) as ready,
              mock.patch.object(supervisor, 'log') as log):
            self.assertTrue(supervisor.recover_snort(snort, stop, {'0'}, False))
        lock.assert_called_once_with(supervisor.SNORT_CONF, blocking=False)
        snort.stop.assert_called_once_with()
        start.assert_called_once_with(snort, stop, 10)
        ready.assert_called_once_with(snort, stop)
        self.assertIn('NFQUEUE 0–3 全部就绪', log.call_args.args[0])

    def test_loop_does_not_keep_restarting_an_unresolved_outage(self):
        clock = 0.0
        stop = mock.Mock()
        snort = mock.Mock()
        snort.alive.return_value = True
        nft = mock.Mock()
        nft.apply.return_value = True, ''
        nft.has_queue.return_value = True

        def wait(seconds):
            nonlocal clock
            clock += seconds
            return stop.is_set()

        stop.is_set.side_effect = lambda: clock >= 400
        stop.wait.side_effect = wait
        with (mock.patch.object(supervisor.sys, 'argv', ['ips-supervisor']),
              mock.patch.object(supervisor.os, 'makedirs'),
              mock.patch.object(supervisor.os.path, 'exists', return_value=True),
              mock.patch.object(supervisor, 'validate_log_storage'),
              mock.patch.object(supervisor.signal, 'signal'),
              mock.patch.object(supervisor.threading, 'Event', return_value=stop),
              mock.patch.object(supervisor.time, 'monotonic', side_effect=lambda: clock),
              mock.patch.object(supervisor, 'Nft', return_value=nft),
              mock.patch.object(supervisor, 'Child', return_value=snort),
              mock.patch.object(supervisor, 'start_snort', return_value=True),
              mock.patch.object(supervisor, 'queue_listeners', side_effect=lambda: ALL if clock < 5 else WITHOUT_0),
              mock.patch.object(supervisor, 'recover_snort', return_value=True) as recover,
              mock.patch.object(supervisor, 'log')):
            self.assertEqual(supervisor.main(), 0)
        recover.assert_called_once_with(snort, stop, {'0'}, False)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux atomic file exchange')
    def test_restart_preserves_native_files_and_leaves_quic_writer_alone(self):
        with tempfile.TemporaryDirectory() as work:
            logs = Path(work) / 'logs'
            logs.mkdir()
            native = logs / '0_file_connector_ndr_transmit'
            native.write_bytes(b'previous event\n')
            quic = logs / '0_quic_observer.json'
            quic.write_bytes(b'current quic event\n')
            inode = native.stat().st_ino
            (Path(work) / 'instance.json').write_text(json.dumps(dict(epoch='fixture', started=0)))
            checkpoint = Path(work) / 'offsets.json'
            checkpoint.write_text(json.dumps(dict(epoch='fixture', files={native.name: dict(inode=inode, offset=native.stat().st_size)})))
            with (mock.patch.object(supervisor, 'NATIVE_LOG_DIR', logs),
                  mock.patch.object(supervisor, 'SNORT_RUNDIR', work),
                  mock.patch.object(supervisor, 'BRIDGE_CHECKPOINT', checkpoint),
                  mock.patch.object(supervisor, 'log')):
                supervisor.archive_native_logs(threading.Event())
            archived, = logs.glob('.response-*/' + native.name)
            self.assertEqual(native.read_bytes(), b'')
            self.assertEqual(archived.read_bytes(), b'previous event\n')
            self.assertEqual(archived.stat().st_ino, inode)
            self.assertEqual(quic.read_bytes(), b'current quic event\n')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux configuration flock')
    def test_nonblocking_restart_shares_existing_configuration_lock(self):
        import fcntl
        from snort_engine import configuration_lock
        with tempfile.TemporaryDirectory() as work:
            config = Path(work) / 'snort.lua'
            with config.with_name('.configuration.lock').open('a') as reload_lock:
                fcntl.flock(reload_lock, fcntl.LOCK_EX)
                with self.assertRaises(BlockingIOError), configuration_lock(config, blocking=False):
                    self.fail('recovery acquired the active reload lock')
            with configuration_lock(config, blocking=False):
                self.assertTrue(config.with_name('.configuration.lock').is_file())


class SupervisorDeployCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.release = self.root / 'release'
        deploy.prepare(self.release)
        self.program = self.root / 'program'
        self.program.mkdir()
        self.original = {}
        for name in deploy.PROGRAMS:
            self.original[name] = (self.release / name).read_bytes() + b'\n# installed predecessor\n'
            (self.program / name).write_bytes(self.original[name])
        proc = self.root / 'proc/201'
        proc.mkdir(parents=True)
        (proc / 'cmdline').write_bytes(b'python3\0' + os.fsencode(self.program / 'ips-supervisor') + b'\0')
        self.pid = self.root / 'snort.pid'
        self.pid.write_text('202')
        patch = mock.patch.multiple(deploy, NATIVE_PROGRAM=self.program, PROC=proc.parent, ENGINE_PID=self.pid,
                                    BACKUPS=self.root / 'backups')
        patch.start()
        self.addCleanup(patch.stop)

    def exercise(self, failure):
        def process(unit):
            return 201 if unit == 'ips.service' else 203

        with (mock.patch('snort_engine.configuration_lock', return_value=nullcontext()),
              mock.patch.object(deploy, 'rule_maintenance', return_value=nullcontext()),
              mock.patch.object(deploy, 'process', side_effect=process),
              mock.patch.object(deploy, 'run', return_value='{"nftables": []}') as run,
              mock.patch.object(deploy, 'wait_ready', side_effect=[RuntimeError('queue failure'), 204] if failure else [204]),
              mock.patch.object(supervisor, 'archive_native_logs'),
              mock.patch.object(deploy, 'load', side_effect=lambda path: supervisor if path.name == 'ips-supervisor' else load('nft_fixture', path))):
            if failure:
                with self.assertRaisesRegex(RuntimeError, 'queue failure'):
                    deploy.upgrade(self.release)
            else:
                deploy.upgrade(self.release)
        return [call.args for call in run.call_args_list if call.args[0] == 'systemctl']

    def test_deploy_restarts_only_detector_service(self):
        self.assertEqual(self.exercise(False), [('systemctl', 'restart', 'ips.service')])
        for name in deploy.PROGRAMS:
            self.assertEqual((self.program / name).read_bytes(), (self.release / name).read_bytes())
            backup, = (self.root / 'backups').glob('*/' + name)
            self.assertEqual(backup.read_bytes(), self.original[name])

    def test_failed_verification_restores_previous_files_and_service(self):
        self.assertEqual(self.exercise(True), [('systemctl', 'restart', 'ips.service'),
                                               ('systemctl', 'stop', 'ips.service'),
                                               ('systemctl', 'start', 'ips.service')])
        for name in deploy.PROGRAMS:
            self.assertEqual((self.program / name).read_bytes(), self.original[name])
