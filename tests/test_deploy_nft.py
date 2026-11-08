"""NFQUEUE-only deployment preserves processes and unrelated live rules."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('nft_deployer', ROOT / 'deploy-nft.py')
deployer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployer)


def table():
    return {'nftables': [
        {'rule': {'family': 'inet', 'table': 'ips', 'chain': 'prerouting', 'handle': 3, 'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}},
                       'right': 'lo'}}, {'return': None}]}},
        {'rule': {'family': 'inet', 'table': 'ips', 'chain': 'prerouting', 'handle': 8, 'expr': [
            {'counter': {'packets': 10, 'bytes': 100}}, {'queue': {'num': {'range': [0, 3]}}}]}}]}


def full_table():
    return {'nftables':[{'table':{'family':'inet','name':'ips','handle':1}},
            {'chain':{'family':'inet','table':'ips','name':'prerouting','handle':2,
                      'type':'filter','hook':'prerouting','prio':-150,'policy':'accept'}}]+table()['nftables']}


class DeployNftCase(unittest.TestCase):
    def test_priority_transaction_rejects_unknown_objects_and_detects_other_policy_changes(self):
        before=full_table();after=copy.deepcopy(before)
        after['nftables'][1]['chain']['prio']=-90
        self.assertEqual(deployer.policy_signature(before),deployer.policy_signature(after))
        after['nftables'][-1]['rule']['expr'][-1]['queue']['num']=7
        self.assertNotEqual(deployer.policy_signature(before),deployer.policy_signature(after))
        before['nftables'].append({'set':{'family':'inet','table':'ips','name':'unexpected'}})
        with self.assertRaises(ValueError):deployer.priority_transaction(before,-90)



    def test_unknown_and_ambiguous_ingress_rules_are_rejected(self):
        data = table()
        self.assertEqual(deployer.ingress_rule(data)['handle'], 3)
        data['nftables'][0]['rule']['expr'][0]['match']['right'] = 'eth0'
        with self.assertRaisesRegex(ValueError, 'Unexpected ingress'):
            deployer.ingress_rule(data)
        data = table()
        data['nftables'].append(copy.deepcopy(data['nftables'][0]))
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            deployer.ingress_rule(data)

    def test_replace_keeps_rule_handle_and_other_rules(self):
        before = table()
        after = copy.deepcopy(before)
        after['nftables'][0]['rule']['expr'] = deployer.LO_EXPR
        after['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 20
        self.assertEqual(deployer.stable_table(before, 3), deployer.stable_table(after, 3))
        after['nftables'][1]['rule']['handle'] = 9
        self.assertNotEqual(deployer.stable_table(before, 3), deployer.stable_table(after, 3))
        command = json.loads(deployer.replacement(before['nftables'][0]['rule'], deployer.LO_EXPR))
        self.assertEqual(command['nftables'][0]['replace']['rule']['handle'], 3)

    def upgrade_fixture(self, failure=False):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            target, release = work / 'installed', work / 'release'
            release.mkdir()
            candidate=original=b'\x7fELF'+bytes(60)
            target.write_bytes(original)
            live = full_table()
            calls = []
            def run(args, text=None):
                calls.append((args, text))
                if 'list' in args:
                    return json.dumps(live)
                if '-j' in args and '-c' not in args:
                    commands = json.loads(text)['nftables']
                    live['nftables']=[entry['add'] for entry in commands if 'add' in entry]
                return ''
            identities = [[[10, 'start'], [11, 'start']]] * 2
            if failure:
                identities[1] = [[10, 'start'], [12, 'changed']]
            with mock.patch.object(deployer, 'TARGET', target), \
                    mock.patch.object(deployer, 'BACKUPS', work / 'backups'), \
                    mock.patch.object(deployer, 'run', side_effect=run), \
                    mock.patch.object(deployer, 'processes', side_effect=identities), \
                    mock.patch('builtins.print'):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, 'identities changed'):
                        deployer.upgrade(release)
                    self.assertEqual(target.read_bytes(), original)
                    self.assertEqual(deployer.policy_signature(live),deployer.policy_signature(full_table()))
                    self.assertEqual(live['nftables'][1]['chain']['prio'],-150)
                else:
                    deployer.upgrade(release)
                    self.assertEqual(target.read_bytes(), candidate)
                    self.assertEqual(deployer.ingress_rule(live)['expr'], deployer.LO_EXPR)
                    self.assertEqual(live['nftables'][1]['chain']['prio'],-90)
            self.assertFalse(any('restart' in args or 'flush' in args or 'delete' in args for args, _ in calls))
            self.assertEqual(len(list((work / 'backups').glob('*/ips-supervisor.before'))), 1)

    def test_upgrade_leaves_processes_and_queue_rule_running(self):
        self.upgrade_fixture()

    def test_failed_verification_restores_file_and_live_rule(self):
        self.upgrade_fixture(failure=True)


if __name__ == '__main__':
    unittest.main()
