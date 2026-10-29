"""三种 TCP 协议（Reality / VMess / VLESS-Encryption）的端口必须校验后再拼链接。

旧实现直接从配置里取 `port` 拼进 URL：被改成 "abc" / True / 70000 / None 时，
链接会变成 `vless://...#:abc`、`vmess` 里 `"port": "True"` 这种客户端一律拒绝的
地址，而面板照样显示「已启用」。Hy2 的 listen_port 早已走 _valid_port，
这三种协议此前漏了。
"""
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

META = {'public_ip': '203.0.113.10', 'server_name': 'node.example.com',
        'listen_port': 443, 'subscription_port': 8443,
        'auth_password': 'master-only', 'cert_type': 'acme',
        'is_insecure': False, 'pin_sha256': ''}
BAD_PORTS = ('abc', True, 70000, -1, None, 0)


class TcpProtocolPortTests(unittest.TestCase):
    def test_reality_skips_invalid_port(self):
        for bad in BAD_PORTS:
            with self.subTest(bad=bad):
                cfg = {'port': bad, 'public_key': 'k', 'short_id': 's',
                       'dest_sni': 'www.apple.com'}
                self.assertEqual(portal.reality_uri_for_user(cfg, 'u1', '203.0.113.10'), '')

    def test_reality_still_builds_for_valid_port(self):
        cfg = {'port': 8443, 'public_key': 'k', 'short_id': 's',
               'dest_sni': 'www.apple.com'}
        self.assertIn(':8443?', portal.reality_uri_for_user(cfg, 'u1', '203.0.113.10'))

    def test_vmess_skips_invalid_port(self):
        for bad in BAD_PORTS:
            with self.subTest(bad=bad):
                cfg = {'domain': 'v.example.com', 'port': bad, 'ws_path': '/ws'}
                self.assertEqual(portal.vmess_uri_for_user(cfg, 'u1', '203.0.113.10'), '')

    def test_vlessenc_skips_invalid_port(self):
        for bad in BAD_PORTS:
            with self.subTest(bad=bad):
                cfg = {'domain': 'e.example.com', 'port': bad,
                       'encryption': 'mlkem768x25519plus.native.600s.x'}
                self.assertEqual(portal.vlessenc_uri_for_user(cfg, 'u1', '203.0.113.10'), '')

    def test_artifacts_omit_nodes_with_invalid_port(self):
        for key, cfg in (
                ('reality', {'port': 'abc', 'public_key': 'k', 'short_id': 's',
                             'dest_sni': 'www.apple.com'}),
                ('vmess', {'domain': 'v.example.com', 'port': True, 'ws_path': '/ws'}),
                ('vlessenc', {'domain': 'e.example.com', 'port': 70000,
                              'encryption': 'mlkem768x25519plus.native.600s.x'})):
            with self.subTest(key=key):
                kw = {key: cfg}
                uri, clash, sing = portal.artifacts(
                    META, auth_override='user-pw', name_override='Hy2-u',
                    user_id='u1', **kw)
                doc = json.loads(sing)
                tags = [o.get('tag', '') for o in doc['outbounds']]
                self.assertFalse([t for t in tags if 'Reality' in t or 'VMess' in t
                                  or 'Enc' in t], tags)
                self.assertNotIn('vless://', uri)
                self.assertNotIn('vmess://', uri)


if __name__ == '__main__':
    unittest.main()
