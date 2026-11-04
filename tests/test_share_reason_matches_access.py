"""分享页的拒绝说明与准入判据同源（2026-11-04 修）。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ShareReasonTests(unittest.TestCase):
    def test_fractional_expiry_second(self):
        user = {'status': 'active', 'expires_at': 100.5}
        self.assertFalse(portal.user_access_allowed(user, 100.7))
        self.assertEqual(portal.share_unavailable_reason(user, 100.7), '服务已到期')

    def test_reasons(self):
        cases = [({'status': 'disabled'}, '账号已被停用'),
                 ({'expires_at': 0}, '服务已到期'),
                 ({'limit_bytes': 5, 'used_bytes': 5}, '流量已超额'),
                 ({'expires_at': 'x'}, '到期时间无效'),
                 ({'limit_bytes': True}, '账号资料无效'),
                 ('junk', '账号资料无效')]
        for user, text in cases:
            with self.subTest(user=user):
                self.assertEqual(portal.share_unavailable_reason(user, 1000), text)


if __name__ == '__main__':
    unittest.main()
