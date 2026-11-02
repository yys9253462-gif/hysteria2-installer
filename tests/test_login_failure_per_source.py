"""一个来源刷错误密码不能把管理员锁在门外（2026-11-03 修）。

旧实现的登录失败桶是全局 10 次 / 10 分钟：知道 token 的人刷 10 次错误密码，
管理员 10 分钟内无法登录。现在按 masquerade 写入的 X-Forwarded-For 分来源。
起真门户进程走真实登录端点。
"""
import http.client
import sys
import time
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class LoginFailurePerSourceTest(surface.EndpointAuthTest):
    def login(self, password, source):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        try:
            conn.request('POST', self.prefix + 'login',
                         body=urllib.parse.urlencode({'username': self.access['username'],
                                                      'password': password}),
                         headers={'Content-Type': 'application/x-www-form-urlencoded',
                                  'X-Forwarded-For': source})
            resp = conn.getresponse()
            body = resp.read()
            return 'hy2_session=' in (resp.getheader('Set-Cookie') or ''), body
        finally:
            conn.close()

    def test_attacker_cannot_lock_out_the_owner(self):
        for _ in range(12):
            self.login('wrong', '198.51.100.20')
            time.sleep(0.03)
        ok, _ = self.login(self.access['password'], '198.51.100.20')
        self.assertFalse(ok, '刷错误密码的来源本身应被锁定')
        ok, body = self.login(self.access['password'], '203.0.113.30')
        self.assertTrue(ok, '另一个来源被一起锁住了：%r' % body[:200])


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(LoginFailurePerSourceTest, _name, None)

if __name__ == '__main__':
    unittest.main()
