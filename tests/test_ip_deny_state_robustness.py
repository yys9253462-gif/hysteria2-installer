"""跨节点拦截表损坏时，/auth 不能被掐断。

`active_ip_deny` 在 /auth 的 data_lock 内被每个新连接调用。表项被写成字符串、
或过期时间被写成非数字时，旧写法 `.items()` / `until <= now` 抛异常，
异常穿透 do_POST → 连接直接断开，客户端只看到重连失败。
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class IpDenyStateTests(unittest.TestCase):
    def test_non_dict_table_is_treated_as_empty(self):
        for bad in (None, 'x', 7, ['u'], True):
            with self.subTest(bad=bad):
                self.assertEqual(portal.active_ip_deny(bad, 'u', 1000), set())

    def test_corrupt_row_is_dropped(self):
        for bad in ('oops', 7, ['1.1.1.1'], None):
            with self.subTest(bad=bad):
                table = {'u': bad}
                self.assertEqual(portal.active_ip_deny(table, 'u', 1000), set())
                self.assertNotIn('u', table)

    def test_corrupt_expiry_is_dropped_but_valid_entries_kept(self):
        table = {'u': {'1.1.1.1': 5000, '2.2.2.2': 'soon', '3.3.3.3': True}}
        self.assertEqual(portal.active_ip_deny(table, 'u', 1000), {'1.1.1.1'})
        self.assertEqual(table['u'], {'1.1.1.1': 5000})

    def test_expired_entries_are_cleared(self):
        table = {'u': {'1.1.1.1': 500}}
        self.assertEqual(portal.active_ip_deny(table, 'u', 1000), set())
        self.assertNotIn('u', table)

    def test_healthy_table_round_trip(self):
        table = {'u': {'1.1.1.1': 5000}, 'other': {'2.2.2.2': 5000}}
        self.assertEqual(portal.active_ip_deny(table, 'u', 1000), {'1.1.1.1'})
        self.assertEqual(table['other'], {'2.2.2.2': 5000})


class IpDenyParseTests(unittest.TestCase):
    def test_parse_rejects_bad_payloads(self):
        for params in ({'user_id': 'bad id', 'ips': []},
                       {'user_id': 'u', 'ips': 'x'},
                       {'user_id': 'u', 'ips': ['not-an-ip']},
                       {'user_id': 'u', 'ips': [], 'ttl': 'x'},
                       {'user_id': 'u', 'ips': [], 'ttl': 5},
                       {'user_id': 'u', 'ips': [], 'ttl': 99999}):
            with self.subTest(params=params):
                with self.assertRaises(ValueError):
                    portal.parse_ip_deny(params, 1000)

    def test_parse_accepts_healthy_payload(self):
        uid, entries = portal.parse_ip_deny(
            {'user_id': 'u', 'ips': ['1.1.1.1', '::1'], 'ttl': 600}, 1000)
        self.assertEqual(uid, 'u')
        self.assertEqual(entries, {'1.1.1.1': 1600, '::1': 1600})


if __name__ == '__main__':
    unittest.main()
