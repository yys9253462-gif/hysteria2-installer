"""面板渲染遇到损坏的用户记录或 ip_tracker 残留格式必须仍能出页面。

regenerate_page 在 /auth 之前、用户操作之后都会跑；它抛异常等于整个控制台白屏，
而节点看起来一切正常（Hysteria / Xray 都是 active）。
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class RenderCorruptStateTests(unittest.TestCase):
    def test_page_html_skips_corrupt_user_records(self):
        meta = {'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
                'subscription_port': 8443, 'listen_port': 1, 'hop_port_range': '',
                'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
                'is_insecure': False, 'pin_sha256': ''}
        users = {'good': {'password': 'x', 'expires_at': 2085974400,
                          'limit_bytes': 0, 'used_bytes': 0, 'status': 'active'},
                 'bad': 'oops', 'none': None}
        page = portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                users=users, token='t', session_secret='s')
        self.assertIn('good', page)
        self.assertNotIn('>oops<', page)

    def test_page_html_tolerates_odd_numeric_fields(self):
        meta = {'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
                'subscription_port': 8443, 'listen_port': 1, 'hop_port_range': '',
                'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
                'is_insecure': False, 'pin_sha256': ''}
        base = {'password': 'x', 'expires_at': 2085974400, 'limit_bytes': 0,
                'used_bytes': 0, 'status': 'active'}
        for extra in ({'ip_limit': '5'}, {'ip_limit': None}, {'ip_limit': 2.7},
                      {'online_ips': 3}, {'online_ips': ['1.1.1.1']},
                      {'online_ips': None}, {'online_ips': {'1.1.1.1': 1}},
                      {'online_ips': 'x'}, {'created_at': 'abc'}):
            with self.subTest(extra=extra):
                page = portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                        users={'u': dict(base, **extra)}, token='t',
                                        session_secret='s')
                self.assertIn('<!doctype html', page.lower())
                self.assertIn('u', page)

    def test_user_page_tolerates_odd_fields(self):
        base = {'status': 'active', 'expires_at': 2085974400, 'limit_bytes': 0,
                'used_bytes': 0}
        for extra in ({'note': 123}, {'note': ['a']}, {'note': ''},
                      {'ip_limit': '5'}, {'ip_limit': None}, {'ip_limit': 2.5}):
            with self.subTest(extra=extra):
                page = portal.user_page_html(
                    'h.example.com', '1.2.3.4', 443, '', 'u', dict(base, **extra),
                    'hysteria2://x@h:1/', 'clash', 'sing', '', 'tok', 'k', sub_port=8443)
                self.assertIn('<!doctype html', page.lower())

    def test_page_html_tolerates_non_dict_user_table(self):
        meta = {'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
                'subscription_port': 8443, 'listen_port': 1, 'hop_port_range': '',
                'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
                'is_insecure': False, 'pin_sha256': ''}
        for bad in (None, ['broken'], 'oops', 7):
            with self.subTest(bad=bad):
                page = portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                        users=bad, token='t', session_secret='s')
                self.assertIn('<!doctype html', page.lower())


class ShareUnavailablePageTests(unittest.TestCase):
    """不可用说明页的 reason 来自用户记录，非字符串时不能 500。

    这条页面本身就是为了「告诉用户为什么连不上」，它挂了就只剩一行裸 403。
    """

    def test_non_string_reason_still_renders(self):
        for bad in (None, 7, ['x'], {'a': 1}, ''):
            with self.subTest(bad=bad):
                page = portal.share_unavailable_html(bad)
                self.assertIn('<!doctype html', page.lower())
                self.assertIn('该链接当前不可用', page)

    def test_reason_is_escaped(self):
        page = portal.share_unavailable_html('<script>x</script>')
        self.assertNotIn('<script>x</script>', page)
        self.assertIn('&lt;script&gt;', page)


if __name__ == '__main__':
    unittest.main()
