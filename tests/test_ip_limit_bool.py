"""ip_limit 写成 JSON true 时，Hy2 与 Reality 必须给出同一个设备上限（2026-11-03 修）。

旧实现：Reality 的 active_ip_limits 跳过 bool（不限设备），Hy2 的 /auth 用
int(True) == 1，把同一个账号限成单设备 —— 第二台设备 Hy2 连不上、Reality 能连。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_auth_per_ip_limit import AuthEndToEndHarness  # noqa: E402
import portal  # noqa: E402


def harness(users):
    h = AuthEndToEndHarness(users)
    # serve() 里的局部常量，单独摘出 /auth 分支时要补进环境。
    h.env.setdefault('IP_TIMEOUT_SECONDS', 180)
    return h


class IpLimitBoolTests(unittest.TestCase):
    def test_true_means_unlimited_on_both_protocols(self):
        users = {'u1': {'password': 'goodpw', 'status': 'active', 'ip_limit': True}}
        self.assertEqual(portal.active_ip_limits(users), {}, 'Reality 侧应视为不限设备')
        h = harness(users)
        first = h.auth('goodpw', '203.0.113.1:1000')
        second = h.auth('goodpw', '203.0.113.2:1000')
        self.assertTrue(first.get('ok'), first)
        self.assertTrue(second.get('ok'), 'Hy2 把 ip_limit=true 当成了 1 台设备：%r' % (second,))

    def test_integer_limit_still_enforced(self):
        h = harness({'u1': {'password': 'goodpw', 'status': 'active', 'ip_limit': 1}})
        self.assertTrue(h.auth('goodpw', '203.0.113.1:1000').get('ok'))
        self.assertFalse(h.auth('goodpw', '203.0.113.2:1000').get('ok'))


if __name__ == '__main__':
    unittest.main()
