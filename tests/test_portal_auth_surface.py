"""端点鉴权覆盖面测试 —— 防「新增端点忘记鉴权」。

起因：门户有 13 个 POST 端点，此前单元测试只覆盖了 AWG 的两个。
剩下 11 个从未被打过，等于没有任何东西阻止「新端点忘了做鉴权检查」。

本测试逐个打全部端点，断言未鉴权时**既拿不到成功、也拿不到任何敏感内容**。
只走未鉴权路径 —— 那是唯一既安全（不触发下载/安装）又能验证鉴权的方式。

覆盖范围来自 portal.py 的真实路由定义；若将来新增端点而没加进下面的清单，
coverage 断言会失败提醒同步（宁可多走一步，也不要悄悄漏测）。
"""
import base64
import http.client
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

META = dict(
    public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
    auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
    hop_port_range='20000-40000', subscription_port=11690,
)

# portal.py 中 `self.path == prefix + '...'` 的全部 POST 端点。
# 新增 POST 端点时必须同步这里。
POST_ENDPOINTS = {
    'do-upgrade', 'install-amneziawg', 'install-gost', 'install-warp',
    'install-xray', 'login', 'logout', 'manage-amneziawg', 'manage-proxy',
    'manage-outbounds', 'manage-reality', 'manage-user', 'manage-vlessenc', 'manage-anytls', 'install-core', 'uninstall-core',
    'manage-vmess', 'manage-warp', 'reboot-server', 'set-bbr',
}

# 集群 API：不带 token 前缀，走 Bearer api_key
CLUSTER_API_POST = {'users/create', 'users/renew', 'users/delete', 'users/list'}
CLUSTER_API_GET = {'node/meta'}

# 敏感串：任何未鉴权响应里都不允许出现
LEAK_MARKERS = ['auth_password', 'obfs_password', 'session_secret',
                'PrivateKey', 'hysteria2://', 'MATCH,PROXY']


class EndpointAuthTest(unittest.TestCase):
    """未鉴权时必须被拒绝，且不得泄露任何敏感内容。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        (cls.root / 'meta.json').write_text(json.dumps(META), encoding='utf-8')
        portal.prepare(cls.root / 'meta.json', cls.port)
        cls.data = json.loads((cls.root / 'portal.json').read_text(encoding='utf-8'))
        cls.access = json.loads((cls.root / 'portal-access.json').read_text(encoding='utf-8'))
        cls.prefix = '/' + cls.data['token'] + '/'
        cls.proc = subprocess.Popen(
            [sys.executable, str(Path(portal.__file__)), 'serve', str(cls.root / 'portal.json')],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(80):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), .1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            cls.proc.kill()
            raise RuntimeError('门户服务未能启动')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()
        cls._tmp.cleanup()

    def request(self, method, path, form=None, auth=None, timeout=8):
        """form 可以是 dict（表单编码）或 str（原始请求体，用于 JSON API）。"""
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        try:
            headers = {'Authorization': auth} if auth else {}
            body = None
            if isinstance(form, dict):
                body = urllib.parse.urlencode(form)
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif isinstance(form, str):
                body = form
                headers['Content-Type'] = 'application/json'
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def assertNoLeak(self, body, label):
        text = body.decode('utf-8', 'ignore')
        for marker in LEAK_MARKERS:
            self.assertNotIn(marker, text,
                             f'{label} 在未鉴权时泄露了 {marker}')

    def test_post_endpoints_declared_match_source(self):
        """portal.py 里新增了 POST 端点却没同步到本文件的清单时报警。"""
        src = (Path(portal.__file__).parent / 'portal.py').read_text(encoding='utf-8')
        found = set()
        import re
        for m in re.finditer(r"self\.path == prefix \+ '([a-z0-9-]+)'", src):
            found.add(m.group(1))
        self.assertEqual(found, POST_ENDPOINTS,
                         'portal.py 的 POST 端点与本测试清单不一致，请同步')

    def test_all_post_endpoints_reject_anonymous(self):
        """未鉴权的 POST 必须被拒：401，或返回登录页 200（仅 login 允许）。
        任何 2xx/3xx 的成功路径都意味着鉴权被绕过。
        """
        for ep in sorted(POST_ENDPOINTS):
            with self.subTest(endpoint=ep):
                status, body = self.request('POST', self.prefix + ep, {})
                if ep == 'login':
                    # login 本身就是登录入口，返回登录页是设计如此
                    self.assertEqual(status, 200, f'{ep} 应返回登录页')
                    self.assertIn(b'login-form', body, f'{ep} 返回的不是登录页')
                elif ep == 'logout':
                    # 退出登录只清 Cookie 并 302 回登录页；不鉴权是刻意的
                    # （会话过期时也必须能退出）。它不解锁任何数据。
                    self.assertEqual(status, 302, f'{ep} 应重定向到登录页')
                else:
                    self.assertEqual(status, 401,
                                     f'{ep} 未鉴权却返回 {status}，疑似鉴权绕过')
                self.assertNoLeak(body, f'POST {ep}')

    def test_wrong_basic_credentials_are_rejected(self):
        bad = 'Basic ' + base64.b64encode(b'admin:wrong-password').decode()
        for ep in sorted(POST_ENDPOINTS - {'login', 'logout'}):
            with self.subTest(endpoint=ep):
                status, body = self.request('POST', self.prefix + ep, {}, bad)
                self.assertIn(status, (401, 403),
                              f'{ep} 接受了错误的凭据（返回 {status}）')
                self.assertNoLeak(body, f'POST {ep} (wrong auth)')

    def test_manage_outbounds_rejects_unknown_target(self):
        raw = f"{self.access['username']}:{self.access['password']}".encode()
        auth = 'Basic ' + base64.b64encode(raw).decode()
        status, body = self.request(
            'POST', self.prefix + 'manage-outbounds',
            {'action': 'rule-add', 'domain': 'example.com', 'outbound': 'not-configured'}, auth)
        self.assertEqual(status, 400, body)
        self.assertIn(b'Unknown outbound target', body)

    def test_query_bearing_management_gets_keep_working(self):
        auth = 'Basic ' + base64.b64encode((self.access['username'] + ':' + self.access['password']).encode()).decode()
        for endpoint in ('warp-status?audit=1', 'proxy-services?audit=1', 'outbounds/list?audit=1', 'upgrade-status?audit=1'):
            status, body = self.request('GET', self.prefix + endpoint, auth=auth)
            self.assertEqual(status, 200, (endpoint, body[:200]))
            self.assertTrue(json.loads(body)['ok'])

    def test_invalid_probe_never_falls_back_to_direct_egress(self):
        auth = 'Basic ' + base64.b64encode((self.access['username'] + ':' + self.access['password']).encode()).decode()
        for query in ('kind=unrecognized', 'kind=socks5&addr='):
            status, body = self.request('GET', self.prefix + 'outbounds/probe?' + query, auth=auth)
            self.assertEqual(status, 400, body)

    def test_invalid_api_payloads_return_json_not_a_broken_connection(self):
        auth = 'Bearer ' + self.data['api_key']
        for payload in ([], {'user_id':42}, {'user_id':'qa-invalid', 'duration_days':-1}):
            status, body = self.request('POST', '/api/v1/users/create', json.dumps(payload), auth)
            self.assertEqual(status, 400, body)
            self.assertFalse(json.loads(body)['ok'])

    def test_cluster_api_requires_valid_api_key(self):
        """集群 API 用 Bearer api_key，错 key / 无 key 都必须是 401。"""
        for sub in sorted(CLUSTER_API_POST):
            with self.subTest(sub=sub):
                for auth in (None, 'Bearer wrong-key'):
                    status, body = self.request('POST', '/api/v1/' + sub, '{}', auth)
                    self.assertEqual(status, 401,
                                     f'/api/v1/{sub} 在 {auth!r} 下未被拒绝')
                    self.assertNoLeak(body, f'/api/v1/{sub}')

        correct = 'Bearer ' + self.data.get('api_key', '')
        status, body = self.request('POST', '/api/v1/users/list', '{}', correct)
        self.assertEqual(status, 200, '正确的 api_key 应当能用')

    def test_cluster_api_get_requires_key(self):
        for sub in sorted(CLUSTER_API_GET):
            with self.subTest(sub=sub):
                for auth in (None, 'Bearer wrong-key'):
                    status, _ = self.request('GET', '/api/v1/' + sub, None, auth)
                    self.assertEqual(status, 401, f'/api/v1/{sub} 未被拒绝')

    def test_management_routes_are_not_reachable_without_prefix(self):
        """门户路由必须带 token 前缀；不带前缀时一律 404（防「猜端点」）。"""
        for ep in ['awg-state', 'warp-status', 'check-version']:
            with self.subTest(endpoint=ep):
                status, _ = self.request('GET', '/' + ep, None, None)
                self.assertEqual(status, 404, f'/{ep} 竟然可以免 token 前缀访问')


if __name__ == '__main__':
    unittest.main()
