"""ACL 里更具体的域名排在前面（2026-11-04 修）。Hysteria 首条命中即停。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class AclRuleOrderTests(unittest.TestCase):
    def test_narrower_rule_precedes_broader_one(self):
        rules = [{'domain': 'google.com', 'outbound': 'warp_socks'},
                 {'domain': 'mail.google.com', 'outbound': 'direct'},
                 {'domain': 'example.org', 'outbound': 'direct'}]
        text = portal.build_acl_block('rules', rules, [], existing_names=['warp_socks'])
        lines = [ln.strip() for ln in text.splitlines() if '(suffix:' in ln]
        self.assertEqual(lines, ['- direct(suffix:mail.google.com)',
                                 '- warp_socks(suffix:google.com)',
                                 '- direct(suffix:example.org)'])


if __name__ == '__main__':
    unittest.main()
