"""AmneziaWG (AWG) 门户集成测试。

覆盖三件事：
  1. 页面确实渲染出了 AWG 卡片与内嵌 JS，且 f-string 插值没有残留占位符；
  2. 新端点在真实 HTTP 往返下的鉴权与返回值形状正确；
  3. 输入校验与信息泄露防护到位（路径穿越、非法名称、私钥不下发）。

不覆盖真正安装 AWG —— 那需要 root 与 Linux，属于 shell 侧
tests/test_awgctl.sh 的职责。
"""
import base64
import http.client
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

# portal.prepare() 需要 qrencode 才能生成订阅二维码。
# 没有它时端点测试无法建立前置数据，直接跳过而不是报错 —— Windows 开发机上
# 属正常情况，CI（Linux，apt install qrencode）会完整执行。
QRENCODE_AVAILABLE = shutil.which('qrencode') is not None


META = dict(
    public_ip='192.0.2.1',
    server_name='hy2.example.com',
    listen_port=27490,
    auth_password='secret-pass',
    obfs_password='obfs-secret',
    is_insecure=False,
    hop_port_range='20000-40000',
    subscription_port=8443,
)


class PageRenderTest(unittest.TestCase):
    """不需要起服务，直接验证渲染结果。"""

    def test_awg_ui_present_in_rendered_page(self):
        page = portal.page_html(
            dict(META), 'hysteria2://x@h:1/', '#sub', 'clash: x', '{}',
            users={}, api_key=None, token='tok', session_secret='sec')

        for needle in [
            'AmneziaWG (抗 DPI 的 WireGuard 分支)',
            'id="awg-badge"',
            'id="awg-meta-chip"',
            'id="btn-install-awg"',
            'id="awg-install-box"',
            'id="awg-line-select"',
            'id="awg-endpoint-input"',
            'id="btn-do-install-awg"',
            'id="awg-panel"',
            'id="awg-peer-name"',
            'id="awg-peer-endpoint"',
            'id="btn-add-awg-peer"',
            'id="awg-peer-tbody"',
            'id="btn-switch-awg-line"',
            'id="btn-update-awg"',
            # 内嵌 JS
            'function loadAwgState',
            'function renderAwgPeers',
            "'awg-state'",
            "'awg-conf?name='",
            "'awg-qr.svg?name='",
            "'install-amneziawg'",
            "'manage-amneziawg'",
            # 样式
            '.awg-card',
            '.awg-table',
        ]:
            self.assertIn(needle, page, f'页面缺少 {needle}')

        # 两种协议线都要能在下拉框里选到
        self.assertIn('value="3"', page)
        self.assertIn('value="2"', page)

    def test_no_unreplaced_placeholder_in_html(self):
        """f-string 写坏花括号会在 HTML 里留下未替换的 {xxx}。
        只看 HTML 部分 —— <script> 里的 {xxx} 是 JS 模板字符串，属正常。"""
        page = portal.page_html(
            dict(META), 'hysteria2://x@h:1/', '#sub', 'clash: x', '{}',
            users={}, api_key=None, token='tok', session_secret='sec')
        html_part = page.split('<script', 1)[0]
        leftovers = re.findall(r'\{[A-Za-z_][A-Za-z0-9_]*\}', html_part)
        self.assertEqual(leftovers, [], f'HTML 中存在未替换的占位符: {leftovers}')

    def test_awg_container_not_leaked_to_user_page(self):
        """AWG 卡片属于管理门户，不应出现在普通用户的连接页里。"""
        user_page = portal.user_page_html(
            'hy2.example.com', 'hy2.example.com', 44321, '', 'u1',
            {'password': 'p'}, 'hysteria2://x@h:1/', 'clash: x', '{}', '', 'tok', 'key')
        self.assertNotIn('awg-badge', user_page)
        self.assertNotIn('loadAwgState', user_page)

    def test_csp_hash_tracks_script_changes(self):
        """CSP 用 SCRIPT 内容的 sha256 白名单。改了 SCRIPT 后哈希必须自动跟上，
        否则浏览器会拒绝执行整段内嵌 JS，门户功能全废。"""
        import hashlib
        digest = base64.b64encode(hashlib.sha256(portal.SCRIPT.encode()).digest()).decode()
        policy = portal.content_policy()
        self.assertIn('sha256-' + digest, policy)
        self.assertNotIn('unsafe-inline', policy)


@unittest.skipUnless(QRENCODE_AVAILABLE, '需要 qrencode 才能构建测试前置数据（Linux/CI 环境）')
class AwgEndpointTest(unittest.TestCase):
    """起真实服务，打真实 HTTP 请求。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]

        (self.root / 'meta.json').write_text(json.dumps(META))
        portal.prepare(self.root / 'meta.json', self.port)
        self.access = json.loads((self.root / 'portal-access.json').read_text())
        self.data = json.loads((self.root / 'portal.json').read_text())
        self.prefix = '/' + self.data['token'] + '/'
        self.auth = 'Basic ' + base64.b64encode(
            (self.access['username'] + ':' + self.access['password']).encode()).decode()

        self.proc = subprocess.Popen(
            [sys.executable, str(Path(portal.__file__)), 'serve', str(self.root / 'portal.json')])
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1', self.port), .1):
                    break
            except OSError:
                time.sleep(.05)

    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        self._tmp.cleanup()

    def get(self, path, auth=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        conn.request('GET', path, headers={'Authorization': auth} if auth else {})
        resp = conn.getresponse()
        out = resp.status, dict(resp.getheaders()), resp.read()
        conn.close()
        return out

    def post(self, path, form, auth=None):
        body = urllib.parse.urlencode(form)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if auth:
            headers['Authorization'] = auth
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.request('POST', path, body=body, headers=headers)
        resp = conn.getresponse()
        out = resp.status, dict(resp.getheaders()), resp.read()
        conn.close()
        return out

    # -------------------------------------------------- awg-state
    def test_awg_state_requires_auth(self):
        self.assertEqual(self.get(self.prefix + 'awg-state')[0], 401)

    def test_awg_state_shape(self):
        status, headers, body = self.get(self.prefix + 'awg-state', self.auth)
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        payload = json.loads(body)
        self.assertTrue(payload['ok'])
        for key in ('installed', 'active', 'line', 'port', 'endpoint', 'peer_count', 'peers', 'ctl'):
            self.assertIn(key, payload, f'awg-state 缺少字段 {key}')
        self.assertIsInstance(payload['peers'], list)
        self.assertIn(payload['line'], ('2', '3'))

    def test_awg_state_never_leaks_private_material(self):
        """哪怕服务器上已有 peer，私钥与预共享密钥也绝不能下发到前端。"""
        _, _, body = self.get(self.prefix + 'awg-state', self.auth)
        text = body.decode('utf-8', 'ignore')
        self.assertNotIn('private_key', text)
        self.assertNotIn('preshared_key', text)

    # -------------------------------------------------- awg-conf / awg-qr.svg
    def test_awg_conf_requires_auth(self):
        """门户对未带凭证的网页请求会返回登录页(200)，带错凭证返回 401。
        要害是：任何一种情况下都不能吐出客户端配置内容。"""
        for route in ('awg-conf?name=phone', 'awg-qr.svg?name=phone'):
            status, _, body = self.get(self.prefix + route)
            self.assertIn(status, (200, 401), f'{route} 返回了意外状态 {status}')
            self.assertNotIn(b'PrivateKey', body, f'{route} 在未鉴权时泄露了 PrivateKey')
            self.assertNotIn(b'[Interface]', body, f'{route} 在未鉴权时泄露了配置内容')
            # 带错误 Basic 凭证必须 401
            self.assertEqual(self.get(self.prefix + route, 'Basic wrong')[0], 401)

    def test_awg_conf_route_is_reachable_with_auth(self):
        """这条断言防的是路由匹配 bug：subpath 含查询串，若比对时没剥掉 ?query，
        带 ?name= 的路由会静默落到 404，功能直接失效。"""
        status, _, body = self.get(self.prefix + 'awg-conf?name=phone', self.auth)
        # 本机未安装 AWG 时应为 404(未安装)；绝不能是 404(路由不存在) 之外的 200/500 以外的异常
        self.assertEqual(status, 404, f'预期未安装返回 404，实际 {status}: {body[:200]}')
        self.assertIn(b'not installed', body)

    def test_awg_conf_rejects_path_traversal_and_bad_names(self):
        """客户端名称必须经过正则校验，挡住目录穿越与注入。"""
        for bad in ['../portal.json', '..%2Fportal.json', 'a/b', '', 'x' * 40,
                    'na me', 'a;rm -rf /', 'a$(whoami)']:
            path = self.prefix + 'awg-conf?' + urllib.parse.urlencode({'name': bad})
            status, _, _ = self.get(path, self.auth)
            self.assertEqual(status, 400, f'名称 {bad!r} 未被拒绝，返回 {status}')

    # -------------------------------------------------- install-amneziawg 校验
    def test_install_requires_auth(self):
        self.assertEqual(self.post(self.prefix + 'install-amneziawg', {'line': '3', 'endpoint': 'vpn.example.com'})[0], 401)

    def test_install_rejects_invalid_line(self):
        for bad in ['9', 'abc', '2,3', '23']:
            status, _, body = self.post(self.prefix + 'install-amneziawg',
                                        {'line': bad, 'endpoint': 'vpn.example.com'}, self.auth)
            self.assertEqual(status, 400, f'协议线 {bad!r} 未被拒绝: {body[:200]}')
            self.assertIn('协议线', json.loads(body)['error'])

    def test_install_defaults_empty_line_to_3(self):
        """line 缺省或为空时按 3.x 处理（前端下拉框一定有值，这是防御性默认）。
        本机没装 AWG 且拉不到 awgctl，因此预期是 500 而不是 400 参数错误。"""
        for empty in ['', '   ']:
            status, _, body = self.post(self.prefix + 'install-amneziawg',
                                        {'line': empty, 'endpoint': 'vpn.example.com'}, self.auth)
            self.assertNotEqual(status, 400, f'空协议线不应被判为参数错误: {body[:200]}')

    def test_install_rejects_missing_endpoint(self):
        status, _, body = self.post(self.prefix + 'install-amneziawg',
                                    {'line': '3', 'endpoint': '   '}, self.auth)
        self.assertEqual(status, 400)
        self.assertIn('连接地址', json.loads(body)['error'])

    def test_install_rejects_port_in_hopping_range(self):
        """落在 20000-40000 的端口会被 Hysteria2 的 iptables 跳跃规则劫持，
        必须在进入安装流程前就拦掉。"""
        for bad_port in ['20000', '25000', '40000']:
            status, _, body = self.post(self.prefix + 'install-amneziawg',
                                        {'line': '3', 'endpoint': 'vpn.example.com', 'port': bad_port},
                                        self.auth)
            self.assertEqual(status, 400, f'端口 {bad_port} 未被拒绝')
            self.assertIn('跳跃区间', json.loads(body)['error'])

    def test_install_rejects_non_numeric_port(self):
        status, _, body = self.post(self.prefix + 'install-amneziawg',
                                    {'line': '3', 'endpoint': 'vpn.example.com', 'port': 'abc'},
                                    self.auth)
        self.assertEqual(status, 400)

    # -------------------------------------------------- manage-amneziawg
    def test_manage_requires_auth(self):
        self.assertEqual(self.post(self.prefix + 'manage-amneziawg', {'action': 'state'})[0], 401)

    def test_manage_state_action(self):
        status, _, body = self.post(self.prefix + 'manage-amneziawg', {'action': 'state'}, self.auth)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)['ok'])

    def test_manage_unknown_action(self):
        status, _, body = self.post(self.prefix + 'manage-amneziawg',
                                    {'action': 'drop-everything'}, self.auth)
        self.assertIn(status, (400, 500))
        if status == 400:
            self.assertIn('未知操作', json.loads(body)['error'])

    def test_manage_rejects_bad_peer_name(self):
        """非法名称必须在触及 shell 之前被拒（返回 400）。"""
        for bad in ['a;rm -rf /', '../x', 'x' * 40, 'na me', 'a$(id)']:
            status, _, body = self.post(self.prefix + 'manage-amneziawg',
                                        {'action': 'peer_add', 'name': bad,
                                         'endpoint': 'vpn.example.com'}, self.auth)
            self.assertEqual(status, 400, f'名称 {bad!r} 未被拒绝: {body[:200]}')


if __name__ == '__main__':
    unittest.main()
