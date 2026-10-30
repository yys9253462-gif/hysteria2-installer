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


class KickConfigRobustnessTests(unittest.TestCase):
    """kick_hy2_users 读的 usage-meter-config.json 被改坏时不能抛异常。

    它在下发拦截后被调用：异常被调用方吞掉，但被拦 IP 的旧会话会一直保持连接。
    """

    def write_cfg(self, payload):
        import json
        import tempfile
        root = Path(tempfile.mkdtemp())
        (root / 'usage-meter-config.json').write_text(json.dumps(payload))
        return root

    def test_corrupt_config_returns_false_without_raising(self):
        for bad in ({'hysteria': 'x'},
                    {'hysteria': {'url': 'http://127.0.0.1:19996'}},
                    {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': None}},
                    {'hysteria': {'url': 7}},
                    ['x'],
                    None):
            with self.subTest(bad=bad):
                root = self.write_cfg(bad)
                self.assertFalse(portal.kick_hy2_users(root, ['u1']))

    def test_non_loopback_url_is_rejected(self):
        root = self.write_cfg({'hysteria': {'url': 'http://1.2.3.4:19996', 'secret': 's'}})
        self.assertFalse(portal.kick_hy2_users(root, ['u1']))

    def test_empty_uid_list_short_circuits(self):
        root = self.write_cfg({'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'}})
        self.assertFalse(portal.kick_hy2_users(root, []))


class ActiveIpLimitsTests(unittest.TestCase):
    """设备上限提取：容器或单条记录损坏时不能抛异常。

    调用点在 iplimit worker 的循环里：抛异常会让整轮设备上限失效，
    所有设备被放行（等于上限形同虚设）。
    """

    def test_non_dict_container_returns_empty(self):
        for bad in (None, 7, 'x', ['a'], True):
            with self.subTest(bad=bad):
                self.assertEqual(portal.active_ip_limits(bad), {})

    def test_corrupt_records_are_skipped(self):
        users = {'bad': 'oops', 'none': None,
                 'good': {'status': 'active', 'ip_limit': 2},
                 'zero': {'status': 'active', 'ip_limit': 0},
                 'negative': {'status': 'active', 'ip_limit': -3},
                 'string': {'status': 'active', 'ip_limit': '5'},
                 'disabled': {'status': 'disabled', 'ip_limit': 4}}
        self.assertEqual(portal.active_ip_limits(users),
                         {'good': 2, 'string': 5})

    def test_boolean_limit_is_not_treated_as_one_device(self):
        # bool 是 int 的子类：True 会被算成 1 个设备，静默把用户限成单设备。
        for bad in (True, False):
            with self.subTest(bad=bad):
                self.assertEqual(portal.active_ip_limits(
                    {'u': {'status': 'active', 'ip_limit': bad}}), {})


class RevocationConfigRobustnessTests(unittest.TestCase):
    """撤销流程读的 usage-meter-config.json 被改坏时，要报明确的
    「无法确认撤销」，而不是把 AttributeError 抛给调用方。

    调用方（apply_access）对任何异常都只是记一行日志并重试；报成
    AttributeError 会把排查方向带偏到代码 bug，而不是坏配置。
    """

    def write_cfg(self, payload):
        import json
        import tempfile
        root = Path(tempfile.mkdtemp())
        if payload is not None:
            (root / 'usage-meter-config.json').write_text(json.dumps(payload))
        return root

    def test_corrupt_config_reports_revocation_uncertainty(self):
        for bad in (None, 7, {'hysteria': 'x'}, {'hysteria': {'url': 'ftp://x'}}, ['x']):
            with self.subTest(bad=bad):
                root = self.write_cfg(bad)
                with self.assertRaises(RuntimeError) as caught:
                    portal.enforce_node_access(root, {'users': {}}, ['u1'])
                self.assertIn('cannot confirm Hy2 revocation', str(caught.exception))


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
