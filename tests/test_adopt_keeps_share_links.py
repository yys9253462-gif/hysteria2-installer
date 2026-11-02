"""重建 portal-access.json 后旧登录会话必须作废，分享链接保持有效（2026-11-03 修）。

ensure_portal_access 重建凭据时先把新 auth_hash 写进 data，adopt 随后比较
`data['auth_hash'] != 新值` 永远为假：用旧密码登录的会话在 30 天内照样有效。
修复用会话纪元作废旧会话，不换 session_secret（它同时是分享链接 k 的密钥）。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class AdoptKeepsShareLinksTests(unittest.TestCase):
    def test_rebuilt_access_keeps_share_key_and_ends_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({'server_name': 'node.example.com', 'public_ip': '192.0.2.1',
                                        'subscription_port': 8443, 'auth_password': 'pw'}),
                            encoding='utf-8')
            before = {'port': 1111, 'token': 'tok', 'api_key': 'k' * 32,
                      'auth_hash': 'a' * 64, 'session_secret': 's' * 64, 'session_epoch': 3,
                      'users': {'buyer': {'password': 'p2', 'view_nonce': 'n1'}},
                      'page': '', 'clash': '', 'sing': '', 'qr': '', 'proxy_services': []}
            (root / 'portal.json').write_text(json.dumps(before), encoding='utf-8')
            # portal-access.json 不存在：adopt 会重建一份新密码。
            with mock.patch.object(portal, 'refresh', lambda *a, **k: None):
                portal.adopt(meta, 2222)
            after = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertNotEqual(after['auth_hash'], before['auth_hash'])
            self.assertEqual(portal.user_view_key(after['session_secret'], 'buyer', 'n1'),
                             portal.user_view_key(before['session_secret'], 'buyer', 'n1'),
                             '重建访问凭据后分享链接 k 变了')
            self.assertGreater(after.get('session_epoch', 0), before['session_epoch'],
                               '旧登录会话没有作废')


    def test_refresh_with_rebuilt_access_also_ends_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({'server_name': 'node.example.com', 'public_ip': '192.0.2.1',
                                        'subscription_port': 8443, 'auth_password': 'pw',
                                        'is_insecure': False, 'listen_port': 443,
                                        'obfs_password': 'o', 'hop_port_range': ''}),
                            encoding='utf-8')
            before = {'port': 1111, 'token': 'tok', 'api_key': 'k' * 32,
                      'auth_hash': 'a' * 64, 'session_secret': 's' * 64, 'session_epoch': 3,
                      'users': {'buyer': {'password': 'p2', 'view_nonce': 'n1'}},
                      'page': '', 'clash': '', 'sing': '', 'qr': '', 'proxy_services': []}
            (root / 'portal.json').write_text(json.dumps(before), encoding='utf-8')
            portal.refresh(meta)
            after = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertEqual(after['session_secret'], before['session_secret'])
            self.assertGreater(after.get('session_epoch', 0), before['session_epoch'])


if __name__ == '__main__':
    unittest.main()
