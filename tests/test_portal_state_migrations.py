"""refresh / adopt 面对老旧或损坏的 portal.json（2026-11-04 修）。

refresh 补出的 users / proxy_services 曾在重读磁盘后被丢掉；adopt 遇到
users 为 null 或机主条目不是 dict 时直接崩溃。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

META = {'server_name': 'node.example.com', 'public_ip': '192.0.2.1', 'subscription_port': 8443,
        'auth_password': 'pw', 'is_insecure': False, 'listen_port': 443,
        'obfs_password': 'o', 'hop_port_range': ''}
ACCESS = {'username': 'u', 'password': 'p', 'api_key': 'k' * 32, 'url': ''}


class PortalStateMigrationTests(unittest.TestCase):
    def _root(self, d, data):
        root = Path(d)
        (root / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
        (root / 'portal-access.json').write_text(json.dumps(ACCESS), encoding='utf-8')
        (root / 'portal.json').write_text(json.dumps(data), encoding='utf-8')
        return root

    def test_refresh_persists_missing_users_and_services(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._root(d, {'port': 1111, 'token': 'tok', 'api_key': 'k' * 32,
                                  'auth_hash': 'a' * 64, 'session_secret': 's' * 64})
            portal.refresh(root / 'client_meta.json')
            after = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertIn(portal.MASTER_USER_ID, after.get('users', {}))
            self.assertEqual(after.get('proxy_services'), [])

    def test_adopt_survives_damaged_users(self):
        for users in (None, [], {portal.MASTER_USER_ID: 'junk'}):
            with self.subTest(users=users), tempfile.TemporaryDirectory() as d:
                root = self._root(d, {'port': 1111, 'token': 'tok', 'api_key': 'k' * 32,
                                      'auth_hash': 'a' * 64, 'session_secret': 's' * 64,
                                      'users': users, 'proxy_services': []})
                with mock.patch.object(portal, 'refresh', lambda *a, **k: None):
                    portal.adopt(root / 'client_meta.json', 2222)
                after = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
                self.assertEqual(after['users'][portal.MASTER_USER_ID]['password'], 'pw')


if __name__ == '__main__':
    unittest.main()
