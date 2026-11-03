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

    def render_user(self, **fields):
        base = {'status': 'active', 'expires_at': 2085974400, 'limit_bytes': 0, 'used_bytes': 0}
        return portal.user_page_html('h.example.com', '1.2.3.4', 443, '', 'u', dict(base, **fields),
                                     'hysteria2://x@h:1/', 'clash', 'sing', '', 'tok', 'k', sub_port=8443)

    def test_user_page_shows_unlimited_for_boolean_ip_limit(self):
        """ip_limit=true 实际不限设备（与鉴权同一判据），页面不能写「1 个网络」（2026-11-03 修）。"""
        page = self.render_user(ip_limit=True)
        self.assertNotIn('1 个网络', page)
        self.assertIn('不限制', page)
        self.assertIn('3 个网络', self.render_user(ip_limit=3))

    def test_infinite_expiry_is_not_shown_as_permanent(self):
        """expires_at=inf 时鉴权拒绝该用户，页面不能写「永久有效」（2026-11-03 修）。"""
        for bad in (float('inf'), 'inf', '1e999', float('nan')):
            with self.subTest(bad=bad):
                self.assertEqual(portal._expiry_text(bad), '到期时间无效')
                self.assertIsNotNone(portal.user_access_denial({'expires_at': bad}, 1))
                page = self.render_user(expires_at=bad)
                self.assertNotIn('永久有效', page)

    def test_page_html_tolerates_non_string_password(self):
        """旧版本会把数字密码原样落盘；单条坏密码不能让整个总览页渲染失败。"""
        meta = {'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
                'subscription_port': 8443, 'listen_port': 1, 'hop_port_range': '',
                'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
                'is_insecure': False, 'pin_sha256': ''}
        base = {'expires_at': 2085974400, 'limit_bytes': 0, 'used_bytes': 0, 'status': 'active'}
        for bad in (123456789, None, ['a', 'b'], {'x': 1}, ''):
            with self.subTest(password=bad):
                page = portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                        users={'good': dict(base, password='abcd-secret-wxyz'),
                                               'bad': dict(base, password=bad)},
                                        token='t', session_secret='s')
                self.assertIn('abcd****wxyz', page)
                self.assertIn('（密码无效）', page)

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


class DownloadArtifactTests(unittest.TestCase):
    """sync_download_artifacts 只写字符串二维码。

    下载端点会对 data['qr'] 调 .encode()：非字符串会让「下载配置」掐断连接。
    """

    def test_non_string_qr_is_not_stored(self):
        for bad in (['a'], 123, {'x': 1}, None, ''):
            with self.subTest(bad=bad):
                data = {}
                portal.sync_download_artifacts(data, 'u', 'clash', 'sing', qr=bad)
                self.assertNotIn('qr', data)
                self.assertEqual((data['clash'], data['sing']), ('clash', 'sing'))

    def test_string_qr_is_stored(self):
        data = {}
        portal.sync_download_artifacts(data, 'u', 'clash', 'sing', qr='<svg/>')
        self.assertEqual(data['qr'], '<svg/>')


class LoginPageEscapingTests(unittest.TestCase):
    """登录页的 token 与错误提示必须被转义/兜底。

    token 来自 portal.json，被改成含引号/尖括号时会原样进 action 属性 ——
    既能破坏登录表单，也是一条自伤 XSS；error_msg 非字符串时 html.escape
    直接抛 AttributeError，登录页变成 500，谁都进不来。
    """

    def test_token_is_html_escaped(self):
        page = portal.login_html('abc"<script>')
        self.assertNotIn('<script>', page.split('action=')[1][:80])
        self.assertIn('&quot;', page)
        self.assertIn('&lt;script&gt;', page)

    def test_non_string_token_does_not_break_the_form(self):
        for bad in (7, None, ['x']):
            with self.subTest(bad=bad):
                page = portal.login_html(bad)
                self.assertIn('action="//login"', page)
                self.assertIn('name="password"', page)

    def test_non_string_error_message_is_ignored(self):
        # CSS 里本来就有 .error-tip 规则，这里断言的是「没有渲染提示块」。
        marker = '<div class="error-tip" role="alert">'
        for bad in (7, ['x'], None, {'a': 1}):
            with self.subTest(bad=bad):
                page = portal.login_html('t', bad)
                self.assertNotIn(marker, page)

    def test_error_message_is_escaped(self):
        page = portal.login_html('t', '<b>x</b>')
        self.assertIn('&lt;b&gt;', page)
        self.assertNotIn('<b>x</b>', page)


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
