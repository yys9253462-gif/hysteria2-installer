"""回归测试：_unreachable_outbounds 正确解析带账密 HTTP、HTTPS 默认端口与 IPv6 出站地址。"""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_unreachable_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)


class _DummySock:
    def close(self):
        pass


class UnreachableOutboundsParseTests(unittest.TestCase):
    def test_http_proxy_with_userinfo_extracts_real_host_and_port(self):
        seen = []

        def fake_connect(addr, timeout=2):
            seen.append(addr)
            return _DummySock()

        outs = [
            {'name': 'auth_http', 'type': 'http', 'url': 'http://demo_user:fake_pass_only@203.0.113.10:8080'},
            {'name': 'https_default', 'type': 'http', 'url': 'https://proxy.example.com'},
            {'name': 'http_v6', 'type': 'http', 'url': 'http://[2001:db8::10]:3128'},
            {'name': 'socks_v6', 'type': 'socks5', 'addr': '[2001:db8::20]:1080'},
        ]
        with patch.object(portal.socket, 'create_connection', side_effect=fake_connect):
            dead = portal._unreachable_outbounds(outs, timeout=1)

        self.assertEqual(dead, [])
        self.assertEqual(
            seen,
            [
                ('203.0.113.10', 8080),
                ('proxy.example.com', 443),
                ('2001:db8::10', 3128),
                ('2001:db8::20', 1080),
            ],
        )

    def test_unreachable_target_still_reported_by_name(self):
        def fake_connect(addr, timeout=2):
            if addr == ('proxy.example.com', 443):
                raise OSError('connection refused')
            return _DummySock()

        outs = [
            {'name': 'alive_auth', 'type': 'http', 'url': 'http://u:fake_only@203.0.113.10:8080'},
            {'name': 'dead_https', 'type': 'http', 'url': 'https://proxy.example.com'},
        ]
        with patch.object(portal.socket, 'create_connection', side_effect=fake_connect):
            dead = portal._unreachable_outbounds(outs, timeout=1)

        self.assertEqual(dead, ['dead_https'])


if __name__ == '__main__':
    unittest.main()
