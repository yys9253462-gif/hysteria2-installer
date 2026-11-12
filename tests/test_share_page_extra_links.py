"""分享页给出其它已启用协议的直链（2026-11-04 加）。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class SharePageExtraLinksTests(unittest.TestCase):
    def page(self, extra):
        return portal.user_page_html('n.example', 'n.example', 443, 'QUIC', 'bob', {'used_bytes': 0},
                                     'hysteria2://x@n.example:443', 'clash', 'sing', '', 'tok', 'k',
                                     8443, extra_links=extra)

    def test_enabled_protocol_links_are_rendered_and_escaped(self):
        html_text = self.page([('Reality', 'vless://u@1.2.3.4:443?a=1&b=<x>'), ('VMess', '')])
        self.assertIn('vless://u@1.2.3.4:443?a=1&amp;b=&lt;x&gt;', html_text)
        self.assertIn('data-copy="u-extra-uri-0"', html_text)
        self.assertNotIn('VMess 直链', html_text, '空链接不应渲染')

    def test_hy2_only_page_is_unchanged(self):
        self.assertNotIn('u-extra-uri', self.page(()))

    def test_extra_links_carry_a_scannable_qr(self):
        """客户在电脑上开分享页、用手机扫码导入：备用节点也要有二维码（2026-11-13 加）。"""
        page = self.page([('Reality', 'vless://u@1.2.3.4:443', '<svg id="qr-reality"></svg>'),
                          ('VMess', 'vmess://x', '')])
        self.assertIn('<svg id="qr-reality"></svg>', page)
        self.assertIn('显示 Reality 二维码', page)
        self.assertNotIn('显示 VMess 二维码', page, '没有二维码时不该渲染空的展开块')
        # 只嵌 SVG：别的内容不进页面；旧的两元组照常渲染。
        self.assertNotIn('<b>x</b>', self.page([('Reality', 'vless://a', '<b>x</b>')]))
        self.assertIn('u-extra-uri-0', self.page([('Reality', 'vless://a')]))


if __name__ == '__main__':
    unittest.main()
