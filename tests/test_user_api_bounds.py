"""users/create 与 users/update 的参数边界与 renew 一致（2026-11-04 修）。

走真实门户进程：update 不接受纯空白密码；create 不接受超过 int64 的额度/用量
（否则之后 renew 永远失败）。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_round2_fixes import PortalServer


class UserApiBoundsTest(PortalServer):  # noqa: E302
    def test_update_rejects_whitespace_password(self):
        self.assertEqual(self.api('users/create', {'user_id': 'ws_pw'})[0], 200)
        self.assertEqual(self.api('users/update', {'user_id': 'ws_pw', 'password': '   '})[0], 400)

    def test_create_rejects_limits_beyond_int64(self):
        for key in ('limit_bytes', 'used_bytes'):
            with self.subTest(key=key):
                st, _ = self.api('users/create', {'user_id': 'big_' + key[0], key: 10 ** 30})
                self.assertEqual(st, 400)
        self.assertEqual(self.api('users/create', {'user_id': 'edge', 'limit_bytes': 2 ** 63 - 1})[0], 200)



class RenewUnlimitedTest(PortalServer):
    def test_adding_traffic_keeps_unlimited_user_unlimited(self):
        self.assertEqual(self.api('users/create', {'user_id': 'unl', 'used_bytes': 50 * 1024 ** 3})[0], 200)
        self.assertEqual(self.api('users/renew', {'user_id': 'unl', 'extend_days': 30, 'add_traffic_gb': 10})[0], 200)
        import json
        users = json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))['users']
        self.assertEqual(users['unl']['limit_bytes'], 0)



class PasswordWhitespaceTest(PortalServer):
    def test_api_rejects_padded_password(self):
        self.assertEqual(self.api('users/create', {'user_id': 'pad1', 'password': 'abc '})[0], 400)
        self.assertEqual(self.api('users/create', {'user_id': 'pad1', 'password': 'abc-pw'})[0], 200)
        self.assertEqual(self.api('users/update', {'user_id': 'pad1', 'password': ' abc'})[0], 400)



if __name__ == '__main__':
    unittest.main()
