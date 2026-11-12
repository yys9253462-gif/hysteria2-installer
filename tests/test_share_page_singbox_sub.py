"""客户分享页的 Sing-box 区块给出订阅链接（2026-11-13 加）。

SFA / SFI 用「远程配置」填链接即可自动更新（响应头本来就带更新间隔）；旧页面只给整段 JSON
和下载按钮，节点换端口后客户得重新导入。
"""
import html
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def textarea(page, element_id):
    m = re.search(r'<textarea id="%s"[^>]*>([^<]*)</textarea>' % re.escape(element_id), page)
    return html.unescape(m.group(1)) if m else None


class SharePageSingBoxSubscriptionTests(unittest.TestCase):
    def page(self, host='n.example'):
        return portal.user_page_html('n.example', host, 443, 'QUIC', 'bob', {'used_bytes': 0},
                                     'hysteria2://x@n.example:443', 'clash', '{"outbounds": []}', '',
                                     'tok', 'k', 8443)

    def test_sing_box_subscription_link_is_offered(self):
        page = self.page()
        self.assertEqual(textarea(page, 'u-sing-sub'), 'https://n.example:8443/tok/u/bob/sing-box.json?k=k')
        self.assertIn('data-copy="u-sing-sub"', page)
        # 原始配置仍在，作为备用
        self.assertEqual(textarea(page, 'u-sing-cfg'), '{"outbounds": []}')

    def test_ipv6_host_is_bracketed(self):
        self.assertEqual(textarea(self.page('2001:db8::1'), 'u-sing-sub'),
                         'https://[2001:db8::1]:8443/tok/u/bob/sing-box.json?k=k')


if __name__ == '__main__':
    unittest.main()
