"""用户密码为空/损坏时，导出链接绝不能回落成节点主密码。

旧写法 `auth_override or m['auth_password']` 把空串、0、None 全当成
「没传覆盖值」：管理员把某个用户的密码清空、或记录被改坏之后，
该用户打开自己的分享页，拿到的 hysteria2 链接里直接是**机主密码**。
机主密码同时是 admin_master 的鉴权密码 —— 等于把自己的账号送出去。
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

META = {'public_ip': '203.0.113.10', 'server_name': 'node.example.com',
        'subscription_port': 8443, 'listen_port': 443,
        'auth_password': 'master-secret-only', 'obfs_password': 'obfs',
        'cert_type': 'acme', 'is_insecure': False, 'pin_sha256': ''}


class ArtifactsPasswordBoundaryTests(unittest.TestCase):
    def test_explicit_empty_user_password_never_falls_back(self):
        # None 是「未提供覆盖值」的默认语义（机主自己的订阅链接），
        # 分享页在调用前已要求密码是非空字符串。
        for value in ('', 0, False):
            with self.subTest(value=value):
                uri, clash, sing = portal.artifacts(
                    META, auth_override=value, name_override='Hy2-u')
                self.assertNotIn('master-secret-only', uri)
                self.assertNotIn('master-secret-only', clash)
                self.assertNotIn('master-secret-only', sing)

    def test_non_string_password_does_not_escape(self):
        for value in (123, ['a'], {'x': 1}, 1.5):
            with self.subTest(value=value):
                uri, _, _ = portal.artifacts(META, auth_override=value, name_override='Hy2-u')
                self.assertNotIn('master-secret-only', uri)

    def test_real_user_password_is_still_used(self):
        uri, _, _ = portal.artifacts(META, auth_override='user-pw', name_override='Hy2-u')
        self.assertIn('user-pw', uri)
        self.assertNotIn('master-secret-only', uri)

    def test_master_password_still_used_when_no_override(self):
        # 节点主页面的默认订阅链接确实该用主密码 —— 那条链接属于机主本人。
        uri, _, _ = portal.artifacts(META, name_override='Hy2-node')
        self.assertIn('master-secret-only', uri)


if __name__ == '__main__':
    unittest.main()
