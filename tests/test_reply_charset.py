"""纯文本回复要声明 UTF-8（2026-11-04 修）。

网页表单的错误回复是中文：旧默认 Content-Type 只有 text/plain，浏览器按本地编码
（常见 GBK / Windows-1252）解码，管理员看到一串乱码。起真门户进程，从网页表单
用一个已存在的密码新建用户，检查 409 回复的 Content-Type 与正文。
"""
import base64
import http.client
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class ReplyCharsetTest(surface.EndpointAuthTest):
    def test_web_form_error_declares_utf8(self):
        raw = f"{self.access['username']}:{self.access['password']}".encode()
        auth = 'Basic ' + base64.b64encode(raw).decode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            body = urllib.parse.urlencode({'action': 'create', 'user_id': 'dup',
                                           'password': 'secret-pass'})  # = 机主密码，必然撞
            conn.request('POST', self.prefix + 'manage-user', body=body,
                         headers={'Authorization': auth,
                                  'Content-Type': 'application/x-www-form-urlencoded'})
            resp = conn.getresponse()
            payload = resp.read()
            self.assertEqual(resp.status, 409, payload[:200])
            self.assertIn('charset=utf-8', resp.getheader('Content-Type', '').lower())
            self.assertIn('密码', payload.decode('utf-8'))
        finally:
            conn.close()


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(ReplyCharsetTest, _name, None)

if __name__ == '__main__':
    unittest.main()
