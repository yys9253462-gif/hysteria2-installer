"""HEAD 请求与 GET 同路由、同状态码，只是没有正文（2026-11-04 修）。

旧实现没有 do_HEAD，BaseHTTPRequestHandler 一律回 501：订阅管理器与可用性探测
用 HEAD 检查链接时，好好的订阅被报成失效。起真门户进程对比 GET 与 HEAD。
"""
import base64
import http.client
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class HeadRequestTest(surface.EndpointAuthTest):
    def call(self, method, path, auth=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            conn.request(method, path, headers={'Authorization': auth} if auth else {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_head_matches_get_without_a_body(self):
        raw = f"{self.access['username']}:{self.access['password']}".encode()
        auth = 'Basic ' + base64.b64encode(raw).decode()
        for path, a in ((self.prefix + 'clash.yaml', auth), ('/api/health', None),
                        (self.prefix + 'clash.yaml', None)):
            with self.subTest(path=path, authed=bool(a)):
                g_status, g_headers, g_body = self.call('GET', path, a)
                h_status, h_headers, h_body = self.call('HEAD', path, a)
                self.assertNotEqual(h_status, 501)
                self.assertEqual(h_status, g_status)
                self.assertEqual(h_body, b'')
                self.assertEqual(h_headers.get('Content-Type'), g_headers.get('Content-Type'))
                self.assertEqual(h_headers.get('Content-Length'), g_headers.get('Content-Length'))


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(HeadRequestTest, _name, None)

if __name__ == '__main__':
    unittest.main()
