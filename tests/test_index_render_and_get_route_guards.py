import ast
import copy
import sys
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _extract_handler_method(name):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(SOURCE, node)
    raise AssertionError(f'missing method {name}')


class TestIndexRenderAndGetRouteGuards(unittest.TestCase):
    def test_subscription_userinfo_handles_non_dict_and_profile_headers_sanitizes_ext(self):
        """subscription_userinfo 须兼容非字典输入，subscription_profile_headers 须净化扩展名防头注入。"""
        self.assertEqual(portal.subscription_userinfo(None), 'upload=0; download=0; total=0; expire=0')
        self.assertEqual(portal.subscription_userinfo(['bad']), 'upload=0; download=0; total=0; expire=0')
        headers = dict(portal.subscription_profile_headers(
            {'server_name': 'node.example.com'}, 'alice', 'yaml"\r\nX-Injected: 1'
        ))
        cd = headers['Content-Disposition']
        self.assertNotIn('\r', cd)
        self.assertNotIn('\n', cd)
        self.assertNotIn('X-Injected', cd)
        self.assertTrue(cd.endswith('.yamlXInjected1"') or cd.endswith('.yaml"'))
        self.assertEqual(cd.count('"'), 2)

    def test_render_index_page_quotes_credentials_and_includes_online_ips(self):
        """_render_index_page 必须对订阅凭据做 URL 编码，并像 regenerate_page 一样填充 online_ips。"""
        src = _extract_handler_method('_render_index_page')
        captured = {}

        def fake_page_html(m, uri, subscription, clash, sing, users=None, **kwargs):
            captured['subscription'] = subscription
            captured['users'] = users
            return '<html>ok</html>'

        now_ts = int(time.time())
        ns = {
            'read_meta_file': lambda p: {'server_name': 'node.example.com', 'subscription_port': 443},
            'meta_path': Path('/tmp/meta.json'),
            'artifacts': lambda m: ('hy2://u', 'clash', '{}'),
            'portal_path': Path('/tmp/portal.json'),
            'read_access_file': lambda p: {'username': 'u@1', 'password': 'p#2:3/4'},
            'meta_display_host': lambda m: 'node.example.com',
            'data_lock': threading.Lock(),
            'data': {
                'users': {'alice': {'status': 'active', 'password': 'pw'}},
                'api_key': 'ak',
                'token': 'tok123',
            },
            'users_list_rows': portal.users_list_rows,
            'user_table': portal.user_table,
            'ip_tracker': {
                'alice': {
                    '1.2.3.4': now_ts - 5,
                    '5.6.7.8': float('nan'),
                    '9.9.9.9': now_ts - 99999,
                }
            },
            'IP_TIMEOUT_SECONDS': 300,
            '_host_for_url': portal._host_for_url,
            'resolve_subscription_port': lambda m: (443, False),
            'page_html': fake_page_html,
            'session_secret': 'sec',
            'quote': portal.quote,
            'time': time,
            '_log_ignored': lambda tag, exc: captured.setdefault('err', exc),
        }
        exec('class _H:\n' + '\n'.join('    ' + ln for ln in src.splitlines()), ns)
        html_out = ns['_H']()._render_index_page()
        self.assertEqual(html_out, '<html>ok</html>', f'unexpected error: {captured.get("err")}')
        self.assertIn('https://u%401:p%232%3A3%2F4@node.example.com:443/tok123/clash.yaml',
                      captured['subscription'])
        self.assertIn('online_ips', captured['users']['alice'])
        self.assertEqual(list(captured['users']['alice']['online_ips'].keys()), ['1.2.3.4'])

    def test_do_get_guards_deepcopy_svg_and_non_string_awg_endpoint(self):
        """do_GET 须深拷贝 users/get 快照、校验分享页/user-config 的 SVG 输出并清洗非字符串 AWG endpoint。"""
        src = _extract_handler_method('do_GET')
        self.assertIn("copy.deepcopy", src)
        self.assertIn("if '<svg' not in qr_svg:", src)
        self.assertIn("isinstance(p.get('endpoint'), str)", src)


if __name__ == '__main__':
    unittest.main()
