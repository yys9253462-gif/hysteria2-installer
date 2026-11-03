"""不限设备的用户，ip_tracker 也不能只增不减（2026-11-03 修）。

旧实现在 ip_limit=0 分支只追加 IP、从不剪掉过期项：移动网络 / CGNAT 下换 IP
频繁的长期在线用户积累成千上万条，users/list 与 /traffic-speed 每次都要遍历。
走真实的 /auth 分支。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_auth_per_ip_limit import AuthEndToEndHarness  # noqa: E402


class IpTrackerBoundedTests(unittest.TestCase):
    def test_unlimited_user_tracker_drops_expired_ips(self):
        h = AuthEndToEndHarness({'u1': {'password': 'goodpw', 'status': 'active', 'ip_limit': 0}})
        stale = {'198.51.100.%d' % i: 1.0 for i in range(200)}
        h.env['ip_tracker']['u1'] = dict(stale)
        self.assertTrue(h.auth('goodpw', '203.0.113.1:1000').get('ok'))
        tracker = h.env['ip_tracker']['u1']
        self.assertIn('203.0.113.1', tracker)
        self.assertFalse(set(stale) & set(tracker), '过期 IP 没有被剪掉')


if __name__ == '__main__':
    unittest.main()
