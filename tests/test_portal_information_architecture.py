"""门户信息架构：服务必须分组在组内子标签里，不能全部纵向堆在同一页。

背景（2026-10-24）：「代理 · WARP · AWG」一页里塞了入站代理、WARP 分流、
自定义出站、AmneziaWG 四块，最长的一块把 AmneziaWG 推到几屏之外，用户以为
功能不存在；Reality 页同样把证书和 BBR 压在 Reality 卡片下面。这里锁住分组
结构，避免以后再加服务时又堆回去。

只断言结构与挂载位置，不复制各卡片的实现细节 —— 那些由各自的测试负责。
"""
import re
import unittest

import portal


def render():
    meta = {
        'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
        'subscription_port': 8443, 'listen_port': 443, 'hop_port_range': '20000-40000',
        'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
        'is_insecure': False, 'pin_sha256': '',
    }
    return portal.page_html(
        meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
        users={}, api_key=None, token='t', session_secret='s')


def _pane(page, pane_id):
    """取一个 tab-pane 的内部 HTML。

    用「下一个 tab-pane 之前」作为边界，而不是配对 </div>：页面里嵌套 div
    很多，正则配对不可靠。子标签 pane 也按同样方式切分。
    """
    start = page.index('id="pane-%s"' % pane_id)
    nxt = page.find('id="pane-', start + 1)
    return page[start:nxt if nxt != -1 else len(page)]


def _sub(pane_html, sub_id):
    start = pane_html.index('id="sub-%s"' % sub_id)
    rest = pane_html[start + 1:]
    m = re.search(r'<div class="subtab-pane', rest)
    return pane_html[start:start + 1 + m.start()] if m else pane_html[start:]


class InformationArchitectureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = render()

    def test_top_level_tabs_are_task_groups(self):
        labels = re.findall(r'class="tab-btn[^"]*" data-tab="([a-z]+)"[^>]*>([^<]+)<', self.page)
        self.assertEqual([t for t, _ in labels],
                         ['connect', 'users', 'proxies', 'reality', 'cores', 'cluster', 'configs'])
        # 标签不再罗列具体服务名，否则每加一个服务都要改标题
        text = dict(labels)
        self.assertNotIn('WARP', text['proxies'])
        self.assertNotIn('AWG', text['proxies'])
        self.assertIn('扩展服务', text['proxies'])
        self.assertIn('备用通道', text['reality'])

    def test_each_service_has_its_own_subtab(self):
        pane = _pane(self.page, 'proxies')
        subs = re.findall(r'data-subtab="([a-z-]+)"', pane)
        self.assertEqual(subs, ['ingress', 'warp', 'outbound', 'awg'])
        for sid in subs:
            self.assertIn('id="sub-%s"' % sid, pane, '缺少子页面 sub-%s' % sid)

    def test_services_are_not_stacked_in_one_subtab(self):
        pane = _pane(self.page, 'proxies')
        owners = {
            'ingress': ['id="proxy-tbody"', 'btn-install-gost'],
            'warp': ['btn-toggle-warp', 'warp-tags-cloud'],
            'outbound': ['ob-list', 'btn-ob-save'],
            'awg': ['awg-peer-tbody', 'btn-install-awg'],
        }
        for sid, needles in owners.items():
            body = _sub(pane, sid)
            for needle in needles:
                self.assertIn(needle, body, '%s 不在 sub-%s 里' % (needle, sid))
        # 关键回归：AWG 不能留在入站代理页
        self.assertNotIn('awg-peer-tbody', _sub(pane, 'ingress'))

    def test_reality_group_separates_cert_and_bbr(self):
        pane = _pane(self.page, 'reality')
        self.assertEqual(re.findall(r'data-subtab="([a-z-]+)"', pane),
                         ['reality-node', 'vmess', 'vlessenc', 'anytls', 'cert', 'bbr'])
        self.assertIn('cert-badge', _sub(pane, 'cert'))
        self.assertIn('bbr-current-text', _sub(pane, 'bbr'))
        self.assertNotIn('cert-badge', _sub(pane, 'reality-node'))
        self.assertNotIn('bbr-current-text', _sub(pane, 'reality-node'))
        # VMess 与 Reality 是两个独立开关，不能混进同一个子页。
        self.assertIn('vmess-badge', _sub(pane, 'vmess'))
        self.assertNotIn('vmess-badge', _sub(pane, 'reality-node'))
        self.assertIn('vlessenc-badge', _sub(pane, 'vlessenc'))
        self.assertNotIn('vlessenc-badge', _sub(pane, 'vmess'))

    def test_subtab_ids_are_unique(self):
        ids = re.findall(r'id="(sub-[a-z-]+)"', self.page)
        self.assertEqual(len(ids), len(set(ids)), '子页面 id 重复')

    def test_subtab_script_supports_direct_links(self):
        """#proxies/awg 这类直达链接必须能打开对应子页。"""
        script = portal.SCRIPT
        self.assertIn('function switchSubtab', script)
        self.assertIn("hash.split('/')", script)
        self.assertIn('data-subtab', script)


if __name__ == '__main__':
    unittest.main(verbosity=2)
