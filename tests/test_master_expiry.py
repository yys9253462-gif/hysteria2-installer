"""机主账号不能在 2036-02-07 过期（2026-11-03 修）。

旧实现给 admin_master 写死 expires_at=2085974400（2036-02-07）。过了那天
/auth 对机主报「User account expired」，而 users/renew / users/update 都拒绝
保留 ID，只能手改 portal.json。新建写 9999-12-31；adopt 把老节点的旧值改掉。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

AFTER_2036 = 2085974400 + 86400


class MasterExpiryTests(unittest.TestCase):
    def node(self, users):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = Path(d.name)
        meta = root / 'client_meta.json'
        meta.write_text(json.dumps({'server_name': 'node.example.com', 'public_ip': '192.0.2.1',
                                    'subscription_port': 8443, 'auth_password': 'pw'}),
                        encoding='utf-8')
        (root / 'portal.json').write_text(json.dumps({
            'port': 1111, 'token': 'tok', 'api_key': 'k' * 32,
            'auth_hash': 'a' * 64, 'session_secret': 's' * 32, 'users': users,
            'page': '', 'clash': '', 'sing': '', 'qr': '', 'proxy_services': []}), encoding='utf-8')
        return root, meta

    def master_after_adopt(self, users):
        root, meta = self.node(users)
        with mock.patch.object(portal, 'refresh', lambda *a, **k: None):
            portal.adopt(meta, 2222)
        return json.loads((root / 'portal.json').read_text(encoding='utf-8'))['users']['admin_master']

    def test_legacy_master_is_still_allowed_after_2036(self):
        master = self.master_after_adopt({'admin_master': {'password': 'pw', 'expires_at': 2085974400,
                                                           'status': 'active'}})
        self.assertIsNone(portal.user_access_denial(master, AFTER_2036), master)

    def test_master_created_by_adopt_is_allowed_after_2036(self):
        master = self.master_after_adopt({'buyer': {'password': 'p2'}})
        self.assertIsNone(portal.user_access_denial(master, AFTER_2036), master)

    def test_master_expiry_set_by_owner_is_kept(self):
        master = self.master_after_adopt({'admin_master': {'password': 'pw', 'expires_at': 1900000000}})
        self.assertEqual(master['expires_at'], 1900000000)


if __name__ == '__main__':
    unittest.main()
