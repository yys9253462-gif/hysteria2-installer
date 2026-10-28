"""前端/功能回归测试 —— 针对本轮实测发现的三类真实缺陷。

缺陷 1（CSP）：门户的 Content-Security-Policy 只有 sha256 哈希白名单、
没有 'unsafe-inline'。任何内联事件处理器（onclick= / onsubmit=）都会被浏览器
**静默丢弃** —— 不报错、不弹窗，按钮就是点了没反应。已踩过三处：
  · 登录页「显示密码」按钮 onclick="toggleSecret(...)"
  · 多用户管理的注销表单 onsubmit="return confirm(...)"（点了直接静默删号！）
  · WARP 分流标签的删除按钮 onclick="delWarpRule(...)"
修法统一为：HTML 里只留 data-*，事件在带哈希的 <script> 里用 addEventListener 绑。

缺陷 2（CSP 哈希漂移）：内联脚本改了而 CSP 仍是旧哈希 → 整段 JS 被拒。
这里直接校验"下发的每个内联 script 的 sha256 都在 CSP 白名单里"。

缺陷 3（机主账号可自毁）：admin_master 的 password 就是 Hysteria 的
auth_password，而 /auth 是遍历 data['users'] 按密码匹配的。面板允许注销它，
一删主密码立刻失效、机主自己都连不上。Web 表单与集群 API 两条路都要堵。
"""
import base64
import hashlib
import http.client
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_hy2_stats  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal
import portal_assets

META = dict(
    public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
    auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
    hop_port_range='20000-40000', subscription_port=11690,
)

# 内联事件属性。注意只匹配「HTML 标签上的属性」，所以扫描前要先剥掉 <script>。
INLINE_EVENT_RE = re.compile(
    r'\son(?:click|submit|change|input|load|keyup|keydown|focus|blur|error'
    r'|mouseover|mouseout|dblclick|contextmenu)\s*=')


def strip_scripts(html):
    """去掉 <script>...</script>，剩下的才是真正的 HTML 标签区。"""
    return re.sub(r'<script\b.*?</script>', '', html, flags=re.S | re.I)


def strip_js_comments(src):
    """剥掉 JS 注释后再断言源码。

    ⚠️ 不剥会误报：代码里解释「为什么不能写内联事件」的注释本身就含有
    onclick=... 这类字面量，会被当成"又写回内联了"。
    """
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return re.sub(r'(?m)^\s*//.*$', '', src)


class FrontendRegressionTest(unittest.TestCase):
    """起一个真实门户服务，直接校验下发的 HTML / CSP / 行为。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        (cls.root / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
        portal.prepare(cls.root / 'client_meta.json', cls.port)
        cls.data = json.loads((cls.root / 'portal.json').read_text(encoding='utf-8'))
        cls.access = json.loads((cls.root / 'portal-access.json').read_text(encoding='utf-8'))
        cls.prefix = '/' + cls.data['token'] + '/'
        cls.auth = 'Basic ' + base64.b64encode(
            f"{cls.access['username']}:{cls.access['password']}".encode()).decode()
        cls.stats = fake_hy2_stats.start(cls.root)
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
        cls.stats.shutdown()
        cls._tmp.cleanup()

    def req(self, method, path, form=None, auth=None, raw=None, timeout=10):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        try:
            headers = {'Authorization': auth} if auth else {}
            body = None
            if isinstance(form, dict):
                body = urllib.parse.urlencode(form)
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif isinstance(raw, str):
                body = raw
                headers['Content-Type'] = 'application/json'
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    # ---------------------------------------------------------------- 缺陷 1

    def test_no_inline_event_handler_in_served_html(self):
        """下发的 HTML 里不得残留内联事件处理器（CSP 下会被静默丢弃）。"""
        for label, auth in (('登录页', None), ('主面板', self.auth)):
            st, hdrs, body = self.req('GET', self.prefix, auth=auth)
            self.assertEqual(st, 200, f'{label} 应可访问')
            html = body.decode('utf-8', 'replace')
            hits = INLINE_EVENT_RE.findall(strip_scripts(html))
            self.assertEqual(hits, [], f'{label} 仍有内联事件处理器 {hits} —— CSP 下会点不动')

    def test_warp_tag_delete_uses_data_attribute_not_inline_onclick(self):
        """WARP 分流标签的删除按钮必须用 data-domain + 事件委托。"""
        src = strip_js_comments(portal_assets.SCRIPT)
        self.assertNotIn('onclick="delWarpRule', src,
                         'WARP 删除标签又写回内联 onclick 了，CSP 下点不动')
        self.assertIn("data-domain=", src, '应改用 data-domain 传参')
        # 必须有容器级委托，否则动态重渲染出来的标签绑不到事件
        self.assertRegex(src, r"warpTagsCloud\.addEventListener\(\s*'click'",
                         '缺少 warpTagsCloud 的 click 事件委托')

    def test_login_password_toggle_has_no_inline_onclick(self):
        """登录页密码显隐按钮：HTML 不带 onclick，由带哈希的脚本绑定。"""
        st, _, body = self.req('GET', self.prefix)
        html = body.decode('utf-8', 'replace')
        self.assertIn('toggle-pwd', html, '登录页应有密码显隐按钮')
        btn = re.search(r'<button[^>]*toggle-pwd[^>]*>', html)
        self.assertIsNotNone(btn)
        self.assertNotRegex(btn.group(0), r'\son\w+=',
                            '密码显隐按钮带了内联事件，CSP 下点不动')
        self.assertRegex(portal_assets.LOGIN_SCRIPT, r"querySelectorAll\('\.toggle-pwd'\)",
                         'LOGIN_SCRIPT 里缺少 .toggle-pwd 的绑定')

    def test_user_delete_form_uses_js_confirm_class(self):
        """注销表单用 class + data-confirm，脚本里挂 submit 拦截并弹确认框。"""
        # 机主账号那一行不渲染删除按钮，所以先建一个普通用户才有注销表单可查
        self.req('POST', self.prefix + 'manage-user',
                 form={'action': 'create', 'user_id': 'tmp_delrow', 'duration_days': '30'},
                 auth=self.auth)
        st, _, body = self.req('GET', self.prefix, auth=self.auth)
        html = body.decode('utf-8', 'replace')
        forms = re.findall(r'<form[^>]*manage-user.*?</form>', html, re.S)
        del_forms = [f for f in forms if 'value="delete"' in f]
        self.assertTrue(del_forms, '主面板应有注销用户的表单')
        for f in del_forms:
            tag = re.match(r'<form[^>]*>', f).group(0)
            self.assertNotRegex(tag, r'\son\w+=',
                                '注销表单带内联 onsubmit，CSP 下会被丢弃 → 无确认直接删号')
            self.assertIn('js-confirm-delete', tag)
        self.assertIn('js-confirm-delete', strip_js_comments(portal_assets.SCRIPT),
                      'SCRIPT 里缺少 .js-confirm-delete 的 submit 拦截')

    # ---------------------------------------------------------------- 缺陷 2

    def _assert_inline_scripts_allowed(self, label, auth):
        st, hdrs, body = self.req('GET', self.prefix, auth=auth)
        self.assertEqual(st, 200)
        csp = hdrs.get('Content-Security-Policy', '')
        self.assertTrue(csp, f'{label} 必须下发 CSP')
        self.assertNotIn("'unsafe-inline'", csp,
                         f'{label} 的 CSP 不应放通 unsafe-inline（那是把防护整体关掉）')
        html = body.decode('utf-8', 'replace')
        scripts = re.findall(r'<script>(.*?)</script>', html, re.S)
        self.assertTrue(scripts, f'{label} 应含内联脚本')
        for i, s in enumerate(scripts):
            h = base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
            self.assertIn(f"'sha256-{h}'", csp,
                          f'{label} 内联 script#{i} 的哈希不在 CSP 白名单，整段 JS 会被拒绝执行')

    def test_inline_script_hashes_match_csp_login(self):
        self._assert_inline_scripts_allowed('登录页', None)

    def test_inline_script_hashes_match_csp_panel(self):
        self._assert_inline_scripts_allowed('主面板', self.auth)

    # ---------------------------------------------------------------- 缺陷 3

    def _hy2_auth(self, password):
        """模拟 Hysteria 的 /auth 动态鉴权。"""
        st, _, body = self.req('POST', '/auth',
                               raw=json.dumps({'auth': password, 'addr': '1.2.3.4:5000',
                                               'tx': 0, 'rx': 0}))
        return json.loads(body.decode())

    def test_master_auth_works_before_any_delete(self):
        """基线：机主主密码能通过 /auth。"""
        self.assertEqual(self._hy2_auth('secret-pass').get('ok'), True,
                         '基线就失败了：主密码应能鉴权通过')

    def test_master_account_cannot_be_deleted_via_web_form(self):
        """Web 表单注销 admin_master 必须被拒，且主密码仍然可用。"""
        st, _, _ = self.req('POST', self.prefix + 'manage-user',
                            form={'action': 'delete', 'user_id': portal.MASTER_USER_ID},
                            auth=self.auth)
        self.assertEqual(st, 400, f'注销机主账号应返回 400，实际 {st}')
        self.assertEqual(self._hy2_auth('secret-pass').get('ok'), True,
                         '机主账号被删掉了 —— 主密码在 /auth 里已失效，机主连不上节点')

    def test_master_account_cannot_be_deleted_via_cluster_api(self):
        """集群 API 同样不允许注销机主账号。"""
        st, _, body = self.req('POST', '/api/v1/users/delete',
                               raw=json.dumps({'user_id': portal.MASTER_USER_ID}),
                               auth='Bearer ' + self.data['api_key'])
        self.assertEqual(st, 400, f'集群 API 注销机主应返回 400，实际 {st}')
        self.assertEqual(self._hy2_auth('secret-pass').get('ok'), True)

    def test_master_row_has_no_delete_button(self):
        """机主那一行的 HTML 里不应出现删除按钮。"""
        st, _, body = self.req('GET', self.prefix, auth=self.auth)
        html = body.decode('utf-8', 'replace')
        rows = re.findall(r'<tr[ >].*?</tr>', html, re.S)
        master_rows = [r for r in rows if portal.MASTER_USER_ID in r]
        self.assertTrue(master_rows, '用户表里应有机主账号那一行')
        for r in master_rows:
            self.assertNotIn('name="action" value="delete"', r,
                             '机主那一行仍在渲染删除按钮')

    def test_normal_user_delete_still_works(self):
        """保护机主的同时，普通用户的注销必须照常可用（别矫枉过正）。"""
        st, _, _ = self.req('POST', self.prefix + 'manage-user',
                            form={'action': 'create', 'user_id': 'tmp_plain',
                                  'duration_days': '30'},
                            auth=self.auth)
        self.assertIn(st, (200, 302))
        st, _, _ = self.req('POST', self.prefix + 'manage-user',
                            form={'action': 'delete', 'user_id': 'tmp_plain'},
                            auth=self.auth)
        self.assertIn(st, (200, 302), '普通用户应能正常注销')

    def test_web_form_rejects_reserved_user_id(self):
        """Web 表单与 REST API 同一规则：placeholder 是 Xray 占位 client 的保留名。"""
        st, _, _ = self.req('POST', self.prefix + 'manage-user',
                            form={'action': 'create', 'user_id': 'placeholder',
                                  'duration_days': '30'},
                            auth=self.auth)
        self.assertEqual(st, 400, f'保留名开户应返回 400，实际 {st}')

    def test_web_form_rejects_out_of_range_duration(self):
        """天数上限与 REST API 一致（1..36500）。"""
        st, _, _ = self.req('POST', self.prefix + 'manage-user',
                            form={'action': 'create', 'user_id': 'tmp_toolong',
                                  'duration_days': '99999999'},
                            auth=self.auth)
        self.assertEqual(st, 400)

    def test_api_create_rejects_non_string_password(self):
        """数字密码会原样落盘，与 /auth、Xray 同步时的 str() 形态对不上。"""
        st, _, _ = self.req('POST', '/api/v1/users/create',
                            raw=json.dumps({'user_id': 'tmp_numpw', 'password': 12345}),
                            auth='Bearer ' + self.data['api_key'])
        self.assertEqual(st, 400)

    # ---- 核心管理页 ----

    def test_cores_status_lists_every_core(self):
        st, _, body = self.req('GET', self.prefix + 'cores-status', auth=self.auth)
        self.assertEqual(st, 200)
        cores = {c['id']: c for c in json.loads(body)['cores']}
        self.assertEqual(set(cores), {'hysteria', 'xray', 'sing-box', 'gost', 'warp', 'amneziawg'})
        self.assertEqual({k for k, c in cores.items() if c['installable']}, {'xray', 'sing-box'})
        for core in cores.values():
            self.assertIn('installed', core)
            self.assertIn('state', core)

    def test_cores_status_requires_auth(self):
        st, _, _ = self.req('GET', self.prefix + 'cores-status')
        self.assertEqual(st, 401)

    def test_install_core_rejects_non_core(self):
        """GOST / WARP / AWG 的安装带配置，不能走纯核心安装接口。"""
        st, _, _ = self.req('POST', self.prefix + 'install-core', form={'name': 'gost'}, auth=self.auth)
        self.assertEqual(st, 400)

    def test_protocol_pages_link_to_cores_instead_of_installing(self):
        st, _, body = self.req('GET', self.prefix, auth=self.auth)
        page = body.decode('utf-8')
        self.assertIn('data-tab="cores"', page)
        for el in ('btn-install-xray', 'vmess-goto-cores', 'vlessenc-goto-cores', 'anytls-goto-cores'):
            tag = re.search(r'<button[^>]*id="%s"[^>]*>' % el, page).group(0)
            self.assertIn('data-goto="cores"', tag, el + ' 应跳转到核心管理，而不是就地安装')


class PageStatusConsistencyTest(unittest.TestCase):
    """管理页的状态展示必须与准入判据 user_access_allowed 同源。"""

    def render(self, users):
        meta = dict(META, cert_type='acme', pin_sha256='')
        return portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                users=users, api_key=None, token='t', session_secret='s')

    def test_missing_status_is_active(self):
        page = self.render({'legacy_user': {'password': 'pw-legacy', 'expires_at': None}})
        row = re.search(r'<tr data-user-row[^>]*>.*?</tr>', page, re.S).group(0)
        self.assertIn('data-state="active"', row)
        self.assertNotIn('已停用', row, '缺 status 的老数据被误显示成「已停用」')

    def test_expiry_at_now_is_expired(self):
        now = int(time.time())
        page = self.render({'edge_user': {'password': 'pw-edge', 'status': 'active', 'expires_at': now}})
        row = re.search(r'<tr data-user-row[^>]*>.*?</tr>', page, re.S).group(0)
        self.assertIn('data-state="inactive"', row)
        self.assertIn('已到期', row)


if __name__ == '__main__':
    unittest.main(verbosity=2)
