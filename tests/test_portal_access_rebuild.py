"""凭据文件丢失后重建的门户密码与首次安装同样 256 位（2026-11-13 修）。

旧实现重建时用 token_urlsafe(18)（144 位），README 写的是「登录密码是 256-bit 随机值」。
"""
import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class RebuiltAccessTest(unittest.TestCase):
    def test_rebuilt_password_is_as_strong_as_a_fresh_install_and_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta = {'public_ip': '203.0.113.7', 'server_name': 'hy2.example.com', 'is_insecure': False,
                    'subscription_port': 8443}
            data = {'token': 't' * 64, 'api_key': 'k' * 32, 'users': {}}
            access, rebuilt = portal.ensure_portal_access(root, meta, data)
            self.assertTrue(rebuilt)
            raw = base64.urlsafe_b64decode(access['password'] + '=' * (-len(access['password']) % 4))
            self.assertGreaterEqual(len(raw) * 8, 256)
            # 新密码能登录：auth_hash 与重建出的凭据对得上，并已落盘。
            digest = hashlib.sha256(base64.b64encode(
                ('%s:%s' % (access['username'], access['password'])).encode())).hexdigest()
            self.assertEqual(data['auth_hash'], digest)
            self.assertEqual(json.loads((root / 'portal-access.json').read_text(encoding='utf-8')), access)


if __name__ == '__main__':
    unittest.main()
