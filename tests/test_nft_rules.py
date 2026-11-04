"""NFQUEUE ingress coverage and existing destination exclusions."""
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('nft_supervisor', str(ROOT / 'ips-supervisor'))
spec = importlib.util.spec_from_loader(loader.name, loader)
supervisor = importlib.util.module_from_spec(spec)
loader.exec_module(supervisor)


class NftRulesCase(unittest.TestCase):
    def test_only_loopback_is_excluded_by_ingress_interface(self):
        rules = supervisor.nft_rules()
        interface_rules = [line.strip() for line in rules.splitlines() if 'iifname' in line]
        self.assertEqual(interface_rules, ['iifname "lo" return'])
        self.assertNotIn('iifname !=', rules)
        self.assertLess(rules.index('iifname'), rules.index('fib daddr'))
        self.assertLess(rules.index('fib daddr'), rules.index('counter queue'))
        self.assertIn('fib daddr type { local, broadcast, multicast } return', rules)
        self.assertIn('ip daddr { 224.0.0.0/4, 255.255.255.255 } return', rules)
        self.assertIn('type filter hook prerouting priority mangle; policy accept;', rules)
        self.assertIn('counter queue flags bypass to 0-3', rules)
        self.assertNotIn('fanout',rules)


if __name__ == '__main__':
    unittest.main()
