"""回归测试：_refresh_portal_state 与 _adopt_locked 拦截非对象 JSON，并修复空/损坏的 api_key、users 与 proxy_services。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class RefreshAndAdoptCorruptStateTests(unittest.TestCase):
    def _setup_dir(self, meta_obj, portal_obj):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        meta_file = root / 'client_meta.json'
        portal_file = root / 'portal.json'
        access_file = root / 'portal-access.json'
        meta_file.write_text(json.dumps(meta_obj), encoding='utf-8')
        portal_file.write_text(json.dumps(portal_obj), encoding='utf-8')
        access_file.write_text(json.dumps({
            'url': 'https://example.com:8443/tok/',
            'username': 'admin',
            'password': 'secret-test-password',
            'api_key': 'valid-access-key',
        }), encoding='utf-8')
        return root, meta_file, portal_file

    def test_refresh_rejects_non_object_meta_or_portal_with_value_error(self):
        _, meta_file, _ = self._setup_dir(['not-an-object'], {'token': 't'})
        with self.assertRaisesRegex(ValueError, 'client_meta.json'):
            portal._refresh_portal_state(str(meta_file))

        _, meta_file2, _ = self._setup_dir(
            {'server_name': 'example.com', 'public_ip': '198.51.100.1', 'port': 443,
             'subscription_port': 8443, 'auth_password': 'pw'},
            ['not-an-object'],
        )
        with mock.patch.object(portal, 'sync_cert_trust', return_value=False), \
             mock.patch.object(portal, 'sync_pin', return_value=None):
            with self.assertRaisesRegex(ValueError, 'portal.json'):
                portal._refresh_portal_state(str(meta_file2))

    def test_adopt_rejects_non_object_json_with_value_error(self):
        _, meta_file, _ = self._setup_dir(
            {'server_name': 'example.com', 'public_ip': '198.51.100.1', 'port': 443,
             'subscription_port': 8443, 'auth_password': 'pw'},
            ['corrupt-portal'],
        )
        with self.assertRaisesRegex(ValueError, 'portal.json'):
            portal._adopt_locked(str(meta_file), 18080)

    def test_refresh_repairs_empty_api_key_and_corrupt_users_and_proxy_services(self):
        _, meta_file, portal_file = self._setup_dir(
            {'server_name': 'example.com', 'public_ip': '198.51.100.1', 'port': 443,
             'subscription_port': 8443, 'auth_password': 'master-pw-test'},
            {'port': 18080, 'token': 'tok123', 'auth_hash': 'h',
             'session_secret': '', 'api_key': '', 'users': None, 'proxy_services': 'broken'},
        )
        with mock.patch.object(portal, 'sync_cert_trust', return_value=False), \
             mock.patch.object(portal, 'sync_pin', return_value=None), \
             mock.patch.object(portal, 'qr_svg_for', return_value='<svg/>'):
            portal._refresh_portal_state(str(meta_file))
        saved = json.loads(portal_file.read_text(encoding='utf-8'))
        self.assertEqual(saved['api_key'], 'valid-access-key')
        self.assertIsInstance(saved['users'], dict)
        self.assertIn(portal.MASTER_USER_ID, saved['users'])
        self.assertIsInstance(saved['proxy_services'], list)


if __name__ == '__main__':
    unittest.main()
