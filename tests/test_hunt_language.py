"""Lucene syntax, bounded parsing and untrusted input must stay data."""
from concurrent.futures import ThreadPoolExecutor
import unittest

from hunt_query import quote
from tests.test_data_layer import m


class HuntLanguageTests(unittest.TestCase):
    def test_ranges_and_field_groups_use_the_same_predicates(self):
        for query,record,expected in (
            ('status:[400 TO 499]',{'status':404},True),
            ('status:{400 TO 499}',{'status':400},False),
            ('status:[400 TO *]',{'status':503},True),
            ('type:(http OR tls)',{'type':'tls'},True),
            ('NOT type:(http OR tls)',{'type':'dns'},True),
            ('src:'+quote('2001:db8::/64'),{'src':'2001:db8::1'},True),
            ('uid:18446744073709551615',{'native_uid':'18446744073709551614'},False),
        ):
            with self.subTest(query=query):
                node=m.hunt_parse(query)
                self.assertEqual(m.hunt_match(node,record),expected)
                self.assertTrue(m.hunt_sql_pushdown(node)[2])

    def test_quoted_and_escaped_wildcards_are_literal(self):
        for query in ('sig:'+quote('literal*mark [tag]'),r'sig:literal\*mark\ \[tag\]'):
            node=m.hunt_parse(query)
            self.assertTrue(m.hunt_match(node,{'sig':'literal*mark [tag]'}))
            self.assertFalse(m.hunt_match(node,{'sig':'literalEXTRAmark t'}))
        self.assertTrue(m.hunt_match(m.hunt_parse('sig:literal*mark'),{'sig':'literalEXTRAmark'}))

    def test_injection_payloads_only_become_bound_values(self):
        for value in ("x' OR 1=1 --",'$(touch /tmp/never-run)',
                      '__import__("os").system("id")','; DROP TABLE events; --'):
            node=m.hunt_parse('sig:'+quote(value));where,args,complete=m.hunt_sql_pushdown(node)
            self.assertTrue(complete)
            self.assertNotIn(value,' '.join(where))
            self.assertIn(value,args)
            self.assertTrue(m.hunt_match(node,{'sig':value}))
            self.assertFalse(m.hunt_match(node,{'sig':'normal evidence'}))

    def test_unsupported_or_excessive_queries_report_errors(self):
        for query in ('sqlite_master:*','sig:/a+$/','sig:test^2','sig:test~2',
                      'status:!=400','src:2001:db8::1','sig:"unfinished',
                      '(' * 24+'type:alert'+')'*24,'x'*8193):
            with self.subTest(query=query[:80]),self.assertRaises(m.HuntError):m.hunt_parse(query)

    def test_parallel_parsers_keep_their_own_field_scope(self):
        queries=['type:(http OR tls)','status:[400 TO 499]','proto:TCP AND type:flow']*20
        expected=[m.hunt_parse(query) for query in queries]
        with ThreadPoolExecutor(max_workers=4) as executor:
            self.assertEqual(list(executor.map(m.hunt_parse,queries)),expected)

    def test_lowercase_connectives_report_errors_instead_of_filtering_on_operator_text(self):
        for query in ('ip_version: 4 and proto: tcp','ip_version:4 Or proto:tcp',
                      'not proto:tcp','proto:(tcp or udp)'):
            with self.subTest(query=query),self.assertRaisesRegex(m.HuntError,'连接词必须大写'):
                m.hunt_parse(query)
        query=m.hunt_parse('ip_version:4 AND proto:tcp')
        self.assertTrue(m.hunt_match(query,dict(ip_version=4,proto='TCP')))
        self.assertFalse(m.hunt_match(query,dict(ip_version=6,proto='TCP')))
        self.assertFalse(m.hunt_match(query,dict(ip_version=4,proto='UDP')))
        self.assertTrue(m.hunt_match(m.hunt_parse('sig:and AND proto:tcp'),dict(sig='and',proto='TCP')))
        self.assertTrue(m.hunt_match(m.hunt_parse('"and" AND proto:tcp'),dict(sig='and',proto='TCP')))


if __name__=='__main__':unittest.main()
