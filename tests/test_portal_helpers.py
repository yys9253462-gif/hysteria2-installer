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


class AdoptWithoutAccessFileTests(unittest.TestCase):
    """portal-access.json 丢失时 adopt 必须重建凭据，而不是清空用户。"""

    def test_rebuilds_access_and_keeps_users(self):
        import json, tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({'server_name': 'node.example.com',
                                        'public_ip': '192.0.2.1',
                                        'subscription_port': 8443}), encoding='utf-8')
            (root / 'portal.json').write_text(json.dumps({
                'port': 1111, 'token': 'tok', 'api_key': 'k' * 32,
                'auth_hash': 'a' * 64, 'session_secret': 's' * 32,
                'users': {'admin_master': {'password': 'pw'}, 'buyer': {'password': 'p2'}},
                'page': '', 'clash': '', 'sing': '', 'qr': '', 'proxy_services': [],
            }), encoding='utf-8')
            with mock.patch.object(portal, 'refresh', lambda *a, **k: None):
                portal.adopt(meta, 2222)
            data = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertEqual(data['port'], 2222)
            self.assertIn('buyer', data['users'], '用户表不能因为凭据文件缺失被清空')
            access = json.loads((root / 'portal-access.json').read_text(encoding='utf-8'))
            self.assertTrue(access['username'])
            self.assertTrue(access['password'])
            self.assertEqual(access['api_key'], 'k' * 32)
            self.assertTrue(access['url'].startswith('https://node.example.com:8443/'))


class MetaFileTests(unittest.TestCase):
    def test_non_object_json_returns_empty_mapping(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client_meta.json'
            for value in ('null', '[]', '"text"', '42'):
                with self.subTest(value=value):
                    path.write_text(value, encoding='utf-8')
                    self.assertEqual(portal.read_meta_file(path), {})

    def test_object_is_preserved(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client_meta.json'
            path.write_text('{"server_name": "node.example.com"}', encoding='utf-8')
            self.assertEqual(portal.read_meta_file(path), {'server_name': 'node.example.com'})


class PageRenderToleranceTests(unittest.TestCase):
    """单条坏数据不能让整张用户表 500（2026-10-30 修复）。"""

    META = {'server_name': 'n.example.com', 'public_ip': '192.0.2.1',
            'listen_port': 19984, 'auth_password': 'p'}

    def _render(self, users):
        return portal.page_html(self.META, 'hysteria2://x', '#s', '{}', '{}',
                                users=users, token='t', session_secret='s')

    def test_corrupt_fields_still_render(self):
        page = self._render({'bad': {'used_bytes': 'x', 'limit_bytes': None,
                                     'expires_at': 'soon', 'created_at': 'y'}})
        self.assertIn('bad', page)

    def test_mixed_created_at_types_sort_without_error(self):
        page = self._render({'a': {'created_at': 'zzz', 'used_bytes': 1},
                             'b': {'created_at': 123, 'used_bytes': 2}})
        self.assertIn('>a<', page)
        self.assertIn('>b<', page)


class FormatBytesTests(unittest.TestCase):
    def test_safe_int_rejects_nonfinite_numbers(self):
        for value in (float('inf'), float('-inf'), float('nan')):
            with self.subTest(value=value):
                self.assertEqual(portal._safe_int(value, 7), 7)

    def test_terabytes(self):
        self.assertEqual(portal.format_bytes(5 * 1024 ** 4), '5.00 TB')

    def test_gigabytes(self):
        self.assertEqual(portal.format_bytes(3 * 1024 ** 3), '3.00 GB')


if __name__ == '__main__':
    unittest.main()
