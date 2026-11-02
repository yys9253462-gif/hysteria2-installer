"""退出登录要在服务端作废会话（2026-11-03 修）。

此前登出只清浏览器 Cookie：被复制走的 hy2_session 在 30 天内照样能用。
起真门户进程：登录拿 Cookie → 登出 → 用同一个 Cookie 访问管理接口必须被拒。
"""
import http.client
import re
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class LogoutInvalidatesSessionTest(surface.EndpointAuthTest):
    def raw(self, method, path, form=None, cookie=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        try:
            headers = {}
            body = None
            if cookie:
                headers['Cookie'] = cookie
            if form is not None:
                body = urllib.parse.urlencode(form)
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.getheader('Set-Cookie') or '', resp.read()
        finally:
            conn.close()

    def login(self):
        _, set_cookie, _ = self.raw('POST', self.prefix + 'login',
                                    {'username': self.access['username'],
                                     'password': self.access['password']})
        m = re.search(r'hy2_session=([^;]+)', set_cookie)
        self.assertTrue(m and m.group(1), set_cookie)
        return 'hy2_session=' + m.group(1)

    def test_copied_cookie_stops_working_after_logout(self):
        cookie = self.login()
        self.assertEqual(self.raw('GET', self.prefix + 'warp-status', cookie=cookie)[0], 200)
        self.raw('POST', self.prefix + 'logout', {}, cookie=cookie)
        self.assertEqual(self.raw('GET', self.prefix + 'warp-status', cookie=cookie)[0], 401,
                         '登出后复制的 Cookie 仍然有效')
        # 重新登录照常可用。
        self.assertEqual(self.raw('GET', self.prefix + 'warp-status', cookie=self.login())[0], 200)

    def test_anonymous_logout_does_not_end_the_owner_session(self):
        cookie = self.login()
        self.raw('POST', self.prefix + 'logout', {})
        self.assertEqual(self.raw('GET', self.prefix + 'warp-status', cookie=cookie)[0], 200,
                         '不带会话的登出把机主踢下线了')


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(LogoutInvalidatesSessionTest, _name, None)

if __name__ == '__main__':
    unittest.main()
