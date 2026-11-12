"""登录表单不因输入环节改写凭据而拒绝正确的人（2026-11-12 修）。

凭据由程序随机生成（用户名是小写十六进制、密码是 urlsafe 串），首尾不会有空白：
* 从聊天软件 / 终端复制常带进首尾空格，旧实现照样判「用户名或密码不正确」；
* 手机输入法默认把普通文本框首字母大写、自动纠错，用户名被改一个字母就登不进去；
* 输错后旧页面连用户名一起清空，随机串每次都得重新找来填。
起真门户进程走真实登录端点。
"""
import html.parser
import http.client
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_portal_auth_surface as surface  # noqa: E402


class _InputCollector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('id'):
            self.inputs[attrs['id']] = attrs


def login_inputs(page):
    collector = _InputCollector()
    collector.feed(page)
    return collector.inputs


class LoginInputToleranceTest(surface.EndpointAuthTest):
    def login(self, username, password, source):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        try:
            conn.request('POST', self.prefix + 'login',
                         body=urllib.parse.urlencode({'username': username, 'password': password}),
                         headers={'Content-Type': 'application/x-www-form-urlencoded',
                                  'X-Forwarded-For': source})
            resp = conn.getresponse()
            body = resp.read().decode('utf-8', 'replace')
            return 'hy2_session=' in (resp.getheader('Set-Cookie') or ''), body
        finally:
            conn.close()

    def test_credentials_with_surrounding_whitespace_are_accepted(self):
        ok, body = self.login(' %s \t' % self.access['username'],
                              self.access['password'] + ' ', '198.51.100.41')
        self.assertTrue(ok, '凭据首尾带空白被拒：%r' % body[:200])

    def test_wrong_password_keeps_the_username_and_focuses_the_password(self):
        ok, body = self.login(self.access['username'], 'wrong-password', '198.51.100.42')
        self.assertFalse(ok)
        inputs = login_inputs(body)
        self.assertEqual(inputs['username'].get('value'), self.access['username'])
        self.assertNotIn('autofocus', inputs['username'])
        self.assertIn('autofocus', inputs['password'])
        self.assertNotIn('value', inputs['password'])
        hostile = '"><script>alert(1)</script>'
        ok, body = self.login(hostile, 'x', '198.51.100.43')
        self.assertFalse(ok)
        self.assertNotIn('<script>alert(1)', body)
        self.assertEqual(login_inputs(body)['username'].get('value'), hostile)

    def test_login_inputs_are_not_rewritten_by_mobile_keyboards(self):
        status, body = self.request('GET', self.prefix)
        self.assertEqual(status, 200)
        inputs = login_inputs(body.decode('utf-8', 'replace'))
        for field in ('username', 'password'):
            with self.subTest(field=field):
                self.assertEqual(inputs[field].get('autocapitalize'), 'none')
                self.assertEqual(inputs[field].get('autocorrect'), 'off')
                self.assertEqual(inputs[field].get('spellcheck'), 'false')
        self.assertIn('autofocus', inputs['username'])
        self.assertNotIn('value', inputs['username'])


for _name in list(vars(surface.EndpointAuthTest)):
    if _name.startswith('test_'):
        setattr(LoginInputToleranceTest, _name, None)

if __name__ == '__main__':
    unittest.main()
