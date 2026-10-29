"""门户辅助函数的小回归集（2026-10-29 修复）。

每条都对应一个「静默错」的真实现象：显示成永久、ACL 引用对不上、
正则把 2087 命中 20870、字节数显示成几千 GB。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ExpiryTextTests(unittest.TestCase):
    def test_missing_expiry_is_permanent(self):
        self.assertEqual(portal._expiry_text(None), '永久有效')

    def test_far_future_date_is_still_a_date(self):
        """十年有效期不能被显示成「永久有效」—— 到期那天会突然停服。"""
        text = portal._expiry_text(2085974400)
        self.assertNotEqual(text, '永久有效')
        self.assertIn('2036', text)

    def test_zero_is_expired(self):
        self.assertEqual(portal._expiry_text(0), '已过期')

    def test_garbage_falls_back_to_permanent(self):
        self.assertEqual(portal._expiry_text('not-a-time'), '永久有效')


class YamlNameTests(unittest.TestCase):
    def test_quoted_and_plain_names_are_both_read(self):
        text = ("outbounds:\n"
                "  - name: direct\n"
                "  - name: 'my_proxy'\n"
                "  - name: \"other\"\n")
        self.assertEqual(portal.outbound_names_in(text), ['direct', 'my_proxy', 'other'])

    def test_single_quote_escape_is_restored(self):
        self.assertEqual(portal._yaml_name_value("'it''s'"), "it's")

    def test_acl_rule_targets_custom_outbound(self):
        """自定义出站名加引号后，ACL 仍必须按原名引用它，不能回退到 direct。"""
        out = portal.render_egress_config(
            "listen: :1\nobfs:\n  type: salamander\n",
            {'warp_enabled': False,
             'warp_rules': [{'domain': 'x.com', 'outbound': 'my_proxy'}],
             'custom_outbounds': [{'name': 'my_proxy', 'type': 'socks5',
                                   'addr': '1.2.3.4:1080'}],
             'outbound_mode': 'rules'})
        self.assertIn('- my_proxy(suffix:x.com)', out)


class NftRuleMatchTests(unittest.TestCase):
    def test_exact_port_only(self):
        rule = portal._nft_port_rule('tcp', 2087)
        self.assertTrue(rule.search('tcp dport 2087 accept # handle 4'))
        self.assertFalse(rule.search('tcp dport 20870 accept # handle 5'))

    def test_protocol_is_distinguished(self):
        rule = portal._nft_port_rule('tcp', 2087)
        self.assertFalse(rule.search('udp dport 2087 accept'))


class FormatBytesTests(unittest.TestCase):
    def test_terabytes(self):
        self.assertEqual(portal.format_bytes(5 * 1024 ** 4), '5.00 TB')

    def test_gigabytes(self):
        self.assertEqual(portal.format_bytes(3 * 1024 ** 3), '3.00 GB')


if __name__ == '__main__':
    unittest.main()
