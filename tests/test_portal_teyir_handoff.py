#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「一键接入 TEYIR 控制台」卡片的行为与安全性回归。

## 为什么要有这个文件

需求原话：「我一台 VPS 搭建好 hysteria2 以后，前端 web 面板直接就可以复制这个
信息，然后我在 teyir 控制台可以直接添加」。

在此之前 portal-access.json 只躺在磁盘上（/etc/hysteria/），操作者必须 SSH 上机器
cat 出来，再手工拼进控制台。本文件把「面板上复制出来的那一串」钉成可验证的对象：

  1. 它与磁盘上的 portal-access.json **逐字节一致** —— 不是"看着差不多"。
     控制台的解析器是严格 JSON.parse，字段名 / 顺序 / 分隔符一旦漂移就会解析失败，
     而两种写法在页面上长得一模一样，靠肉眼完全看不出来。
  2. 四个键齐全，且 url 形如 https://host:port/<token>/。
     少了尾部斜杠控制台就提不出 {token} 段，结果是**节点登记成功、但「节点运维」
     整片页签不可用**，报错还指向别处（"缺少门户路径段"）—— 排查成本极高。
  3. 凭据经过 HTML 转义。password 是 token_urlsafe，虽然不含 <>&，但 url 与
     username 在别处未必，且将来若换生成方式就会踩坑 —— 这里从行为上兜住。
  4. **未登录的访客一项都看不到**：登录页不得出现任何凭据。
     凭据此前已经以明文坐在订阅链接里（clash-subscription 那条
     https://user:password@host:port/…），所以把四项单列**没有引入新的暴露面**；
     但"没有新暴露面"必须是被验证的结论，不能是假设。
  5. portal.py 里**每一处** page_html() 调用都传了 username/password。
     三个调用点（prepare / refresh / regenerate_page）漏任何一个，都会让页面
     看起来完全正常，只有真去点复制才发现是空的 —— 静默且难以复现。
     这一条用 AST 扫源码，而不是靠"我记得改了"。
"""
import ast
import html as html_mod
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

REPO_ROOT = Path(portal.__file__).parent

META = dict(
    public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
    auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
    hop_port_range='20000-40000', subscription_port=11690,
)

TOKEN = 'a' * 64
API_KEY = 'hy2_sec_' + 'b' * 32
USER = 'f3a7db9728e9d333'
PASS = 'EWqJRf5wXn6AtrJlebljrtzRFIT0abcXYZ-'
EXPECTED_ACCESS_URL = 'https://hy2.example.com:11690/' + TOKEN + '/'


def render(**overrides):
    """渲染一份首页 HTML。参数可覆盖默认凭据，便于测转义。"""
    kw = dict(username=USER, password=PASS)
    kw.update(overrides)
    return portal.page_html(
        META,
        uri='hysteria2://master@hy2.example.com:27490/?insecure=0',
        subscription='https://%s:%s@hy2.example.com:11690/%s/clash.yaml' % (kw['username'], kw['password'], TOKEN),
        clash='proxies: []', sing='{}', users={}, api_key=API_KEY, token=TOKEN,
        session_secret='s' * 64, **kw)


def by_id(page, identifier):
    """取某个 id 的元素内容（div 或 textarea 都吃），并反转义。"""
    pattern = (r'<(?P<tag>div|textarea)[^>]*\bid="%s"[^>]*>(?P<body>.*?)</(?P=tag)>'
               % re.escape(identifier))
    match = re.search(pattern, page, re.S)
    if not match:
        raise AssertionError('页面里找不到 id=%s 的元素' % identifier)
    return html_mod.unescape(match.group('body'))


class ConsoleHandoffTest(unittest.TestCase):
    """卡片渲染出来的内容必须是控制台能直接吃下的形态。"""

    @classmethod
    def setUpClass(cls):
        cls.page = render()

    # ------------------------------------------------- 与控制台解析器的契约

    def test_copied_json_is_byte_identical_to_the_disk_file(self):
        """面板复制的字节 == prepare() 写盘 /etc/hysteria/portal-access.json 的字节。

        两边都经 portal_access_payload() 构造，所以这里是"构造保证"的守门人：
        谁把它拆成两处各写各的，这条立刻红。
        """
        expected = json.dumps(
            portal.portal_access_payload(EXPECTED_ACCESS_URL, USER, PASS, API_KEY),
            ensure_ascii=False)
        self.assertEqual(by_id(self.page, 'teyir-access-json'), expected)

    def test_payload_is_valid_json_with_the_four_fields_the_console_reads(self):
        payload = json.loads(by_id(self.page, 'teyir-access-json'))
        self.assertEqual(sorted(payload), ['api_key', 'password', 'url', 'username'])
        self.assertEqual(payload['url'], EXPECTED_ACCESS_URL)
        self.assertEqual(payload['username'], USER)
        self.assertEqual(payload['password'], PASS)
        self.assertEqual(payload['api_key'], API_KEY)

    def test_url_carries_the_trailing_slash_the_console_needs(self):
        """url 必须能反解出 {token} 段。

        控制台侧从 url 的路径里取 token；少了尾部斜杠就取不到，
        症状是节点登记成功但「节点运维」页签整片灰色 —— 与真实原因相隔很远。
        """
        url = json.loads(by_id(self.page, 'teyir-access-json'))['url']
        tail = re.fullmatch(r'https://[^/]+/([0-9a-fA-F]+)/', url)
        self.assertIsNotNone(tail, 'url 形状不符合 https://host:port/<token>/：%r' % url)
        self.assertEqual(tail.group(1), TOKEN)

    def test_url_host_port_matches_what_the_api_card_advertises(self):
        """同一页上「API 基础地址」与本卡片的门户地址必须指向同一个 host:port。

        两者若漂移，操作者会拿一个能连、另一个连不上的地址，且都在同一家面板上。
        """
        api_base = by_id(self.page, 'api-base-val')
        access_url = json.loads(by_id(self.page, 'teyir-access-json'))['url']
        self.assertTrue(access_url.startswith(api_base + '/'),
                        '%r 不是以 %r 开头' % (access_url, api_base))

    # ------------------------------------------------- 逐字段（控制台手工填写路径）

    def test_the_four_individual_rows_expose_the_same_values(self):
        """控制台也支持按字段手填，四行必须与大 JSON 完全一致。"""
        for identifier, expected in [
            ('teyir-url-val', EXPECTED_ACCESS_URL),
            ('teyir-user-val', USER),
            ('teyir-pass-val', PASS),
            ('teyir-key-val', API_KEY),
        ]:
            self.assertEqual(by_id(self.page, identifier), expected,
                             '%s 的内容与凭据不一致' % identifier)

    def test_every_handoff_field_has_a_copy_button(self):
        for identifier in ('teyir-access-json', 'teyir-url-val',
                           'teyir-user-val', 'teyir-pass-val', 'teyir-key-val'):
            self.assertIn('data-copy="%s"' % identifier, self.page,
                          '%s 没有配复制按钮' % identifier)

    def test_every_copy_button_targets_an_element_that_exists(self):
        """孤儿 data-copy 会让复制按钮点了毫无反应（field 为 null 直接抛异常）。

        全页面扫，不只扫本卡片 —— 顺带守住别处。
        """
        targets = re.findall(r'data-copy="([^"]+)"', self.page)
        self.assertIn('teyir-access-json', targets)
        ids = set(re.findall(r'\bid="([^"]+)"', self.page))
        missing = sorted(set(targets) - ids)
        self.assertEqual(missing, [], '这些 data-copy 指向不存在的 id：%s' % missing)

    # ------------------------------------------------- 转义 / 不被捅破

    def test_credentials_with_html_metacharacters_cannot_break_out(self):
        """password 里塞 <script> 也必须原样躺在 textarea 里，不能变成标签。"""
        nasty_pass = 'p<script>alert(1)</script>&"\''
        nasty_user = 'u<i>&amp;</i>'
        page = render(username=nasty_user, password=nasty_pass)

        raw = re.search(r'<textarea[^>]*id="teyir-access-json"[^>]*>(.*?)</textarea>',
                        page, re.S).group(1)
        self.assertNotIn('<script>', raw)
        self.assertNotIn('<i>', raw)

        payload = json.loads(html_mod.unescape(raw))
        self.assertEqual(payload['password'], nasty_pass)
        self.assertEqual(payload['username'], nasty_user)
        # 逐字段那几行同样不能破
        self.assertEqual(by_id(page, 'teyir-pass-val'), nasty_pass)
        self.assertEqual(by_id(page, 'teyir-user-val'), nasty_user)

    def test_missing_credentials_render_an_empty_string_not_the_literal_none(self):
        """prepare() 之前的页面上没有凭据时，显示的应是空串。

        若渲染成 Python 的 "None"，操作者会把它当成真密码粘进控制台，
        然后拿到一个 "门户凭据校验未通过" 的报错 —— 指向完全错误的方向。
        """
        page = render(username='', password='')
        payload = json.loads(by_id(page, 'teyir-access-json'))
        self.assertEqual(payload['username'], '')
        self.assertEqual(payload['password'], '')
        self.assertNotIn('None', payload['username'])
        self.assertNotIn('None', payload['password'])

    # ------------------------------------------------- 未登录者看不到凭据

    def test_login_page_leaks_no_credential(self):
        """登录页是唯一对未认证访客开放的页面，它一个字段都不能带。"""
        login = portal.login_html(TOKEN)
        for secret in (USER, PASS, API_KEY, 'teyir-access-json'):
            self.assertNotIn(secret, login,
                             '登录页泄漏了 %s' % secret[:12])

    def test_user_self_service_page_leaks_no_admin_credential(self):
        """普通用户的专属连接页也不得带上机主凭据。"""
        user_page = portal.user_page_html(
            'hy2.example.com', 'hy2.example.com', 27490, 'QUIC', 'buyer_01',
            {'password': 'user-pass', 'expires_at': 2085974400, 'ip_limit': 1,
             'limit_bytes': 0, 'used_bytes': 0, 'status': 'active',
             'created_at': 0, 'note': ''},
            'hysteria2://user@host:1/', 'proxies: []', '{}', '<svg/>',
            TOKEN, 'user-key', 11690)
        for secret in (USER, PASS, API_KEY, 'teyir-access-json'):
            self.assertNotIn(secret, user_page,
                             '用户专属页泄漏了 %s' % secret[:12])

    # ------------------------------------------------- 静态：没有别的出口

    def test_the_payload_builder_is_not_reachable_from_the_bearer_api(self):
        """api_key 权限低于 Basic，用低权限凭据换高权限凭据就是提权。

        /api/v1/ 那套走 Bearer（api_key），/{token}/ 那套才走 Basic。
        portal_access_payload() 只许出现在写盘与网页渲染两处，
        一旦有人顺手把它挂到 /api/v1/ 上，这条会红。
        """
        src = (REPO_ROOT / 'portal.py').read_text(encoding='utf-8')
        callers = set()
        for node in ast.walk(ast.parse(src)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'portal_access_payload'):
                callers.add(node.lineno)

        # prepare() 写盘 + page_html() 渲染 + adopt() 重建缺失的凭据文件
        # （2026-10-30 新增：portal-access.json 丢失时在 CLI 路径里重建，
        #   保留用户与 API Key；它不在任何 HTTP 路由内，下面的窗口检查仍然生效）。
        allowed = 3
        self.assertEqual(len(callers), allowed,
                         'portal_access_payload 的调用点数量变了（%s 处，行号 %s）——'
                         '新增的出口必须确认只挂在 Basic 鉴权的网页链路上'
                         % (len(callers), sorted(callers)))

        for start in callers:
            # 只看**代码**，先剥掉注释行 —— 解释「为什么不能挂到 /api/v1/」的注释
            # 本身就含这个字面量，不剥会自伤。
            window = '\n'.join(
                line for line in src.splitlines()[max(0, start - 12):start + 2]
                if not line.lstrip().startswith('#'))
            self.assertNotIn('api/v1', window,
                             '第 %d 行附近像是把凭据挂到了 Bearer API 上' % start)


class PageHtmlCallSitesTest(unittest.TestCase):
    """三个调用点一个都不能漏传凭据 —— 用 AST 扫，不靠记性。"""

    @classmethod
    def setUpClass(cls):
        cls.src = (REPO_ROOT / 'portal.py').read_text(encoding='utf-8')
        cls.tree = ast.parse(cls.src)

    def test_signature_accepts_credentials(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'page_html':
                names = {a.arg for a in node.args.args}
                self.assertIn('username', names)
                self.assertIn('password', names)
                return
        self.fail('portal.py 里找不到 page_html 的定义')

    def test_every_call_site_passes_both_credentials(self):
        sites = []
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'page_html'):
                sites.append(node)
        self.assertEqual(len(sites), 3,
                         'page_html 的调用点数量变了（%d 处）；'
                         '新增的入口必须一并传 username/password' % len(sites))
        for node in sites:
            passed = {kw.arg for kw in node.keywords}
            self.assertIn('username', passed,
                          'portal.py:%d 的 page_html 调用漏了 username' % node.lineno)
            self.assertIn('password', passed,
                          'portal.py:%d 的 page_html 调用漏了 password' % node.lineno)

    def test_prepare_writes_the_file_through_the_same_builder(self):
        """prepare() 必须用 portal_access_payload 写盘。

        若它退回自己拼 dict，面板复制的与磁盘上的就可能悄悄分家。
        """
        found = False
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'portal_access_payload'):
                # 落在 prepare() 函数体内？
                for func in ast.walk(self.tree):
                    if (isinstance(func, ast.FunctionDef) and func.name == 'prepare'
                            and func.lineno <= node.lineno
                            <= max(getattr(n, 'lineno', 0) for n in ast.walk(func))):
                        found = True
        self.assertTrue(found, 'prepare() 没有使用 portal_access_payload() 写盘')


class CardPlacementTest(unittest.TestCase):
    """卡片要出现在操作者找得到的地方，且不要污染别的页签。"""

    def test_card_lives_in_the_cluster_pane(self):
        page = render()
        pane = re.search(r'<div class="tab-pane" id="pane-cluster">(.*?)\n</div>\s*\n',
                         page, re.S)
        self.assertIsNotNone(pane)
        self.assertIn('id="teyir-join-card"', pane.group(1))

    def test_tab_label_mentions_the_console(self):
        """入口藏在一个叫「通用 REST API 对接」的页签里没人会点开。"""
        self.assertIn('接入控制台', render())


if __name__ == '__main__':
    unittest.main(verbosity=2)
