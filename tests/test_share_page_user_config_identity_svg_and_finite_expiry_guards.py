"""回归测试：分享页脏身份防回落 localhost、提前 404、user-config 有限到期与备注清洗、extra_links SVG/标签防护与非字典 uinfo 容错。"""

import ast
import json
import math
import re
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _extract_do_get(extra_ns):
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'do_GET':
            src = ast.get_source_segment(PORTAL_SRC, node)
            dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
            ns = {
                'json': json,
                're': re,
                'math': math,
                'hmac': __import__('hmac'),
                'time': __import__('time'),
                'Path': Path,
                'parse_qs': parse_qs,
                'VALID_USER_ID_RE': portal.USER_ID_RE,
                'ANYTLS_SERVICE': portal.ANYTLS_SERVICE,
                'TUIC_SERVICE': portal.TUIC_SERVICE,
                'QR_UNAVAILABLE_SVG': portal.QR_UNAVAILABLE_SVG,
                '_STATUS_PILL_TEXT': portal._STATUS_PILL_TEXT,
                'user_table': portal.user_table,
                'user_view_key': portal.user_view_key,
                'user_share_available': portal.user_share_available,
                'share_unavailable_reason': portal.share_unavailable_reason,
                'share_unavailable_html': portal.share_unavailable_html,
                'clean_node_identity': portal.clean_node_identity,
                '_clean_host_scalar': portal._clean_host_scalar,
                '_valid_port': portal._valid_port,
                'artifacts': portal.artifacts,
                'subscription_userinfo': portal.subscription_userinfo,
                'subscription_profile_headers': portal.subscription_profile_headers,
                'user_access_denial': portal.user_access_denial,
                '_expiry_text': portal._expiry_text,
                '_safe_int': portal._safe_int,
                '_display_ip_limit': portal._display_ip_limit,
                'user_page_html': portal.user_page_html,
                'resolve_subscription_port': portal.resolve_subscription_port,
                '_log_ignored': lambda *a, **kw: None,
            }
            ns.update(extra_ns)
            exec(dedented, ns)
            return ns['do_GET']
    raise AssertionError('未找到 do_GET')


class _FakeGetHandler:
    def __init__(self, path, authed=True):
        self.path = path
        self.headers = {}
        self._authed = authed
        self.resp = None

    def is_authenticated(self):
        return self._authed

    def check_rate_limit(self, bucket='web'):
        return True

    def record_failure(self):
        pass

    def _extend_deadline(self, seconds, heavy=False):
        return True

    def _user_extra_links(self, uid, pub, with_qr=False):
        return []

    def reply(self, code, body, ctype='text/plain', extra_headers=()):
        self.resp = (code, body, ctype, extra_headers)
        return self.resp

    def reply_json(self, code, payload):
        self.resp = (code, payload)
        return self.resp


class SharePageUserConfigIdentitySvgAndFiniteExpiryGuardsTests(unittest.TestCase):
    def test_share_route_rejects_control_char_meta_identity_instead_of_localhost(self):
        """u/<uid> 面对仅含控制字符/空白的损坏 server_name/public_ip 必须返回 503，不得回落 localhost。"""
        data = {'token': 'tok1', 'users': {'u1': {'password': 'pw1', 'status': 'active', 'view_nonce': 'n1'}}}
        fn = _extract_do_get({
            'data': data,
            'data_lock': threading.Lock(),
            'session_secret': 'sec',
            'meta_path': Path('/tmp/meta.json'),
            'read_meta_file': lambda p: {'server_name': 'bad\nhost', 'public_ip': '1.2.3.4\r\nevil', 'listen_port': 443},
            '_active_reality_config': lambda: None,
            '_active_vmess_config': lambda: None,
            '_active_vlessenc_config': lambda: None,
            '_active_anytls_config': lambda: None,
            '_active_tuic_config': lambda: None,
            '_served_singbox_config': lambda cfg, svc: None,
            'subprocess': SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(stdout=b'<svg></svg>')),
        })
        h = _FakeGetHandler('/tok1/u/u1', authed=True)
        fn(h)
        self.assertEqual(h.resp[0], 503, f'脏身份应被拒返回 503，实际: {h.resp[0]}')

    def test_share_route_unknown_subfile_returns_404_before_artifacts(self):
        """u/<uid>/unknown 必须在调用 artifacts 之前直接返回 404。"""
        called = []
        data = {'token': 'tok1', 'users': {'u1': {'password': 'pw1', 'status': 'active', 'view_nonce': 'n1'}}}
        fn = _extract_do_get({
            'data': data,
            'data_lock': threading.Lock(),
            'session_secret': 'sec',
            'meta_path': Path('/tmp/meta.json'),
            'read_meta_file': lambda p: (called.append('meta') or {'server_name': 'vpn.example.com'}),
        })
        h = _FakeGetHandler('/tok1/u/u1/not-a-file', authed=True)
        fn(h)
        self.assertEqual(h.resp[0], 404)
        self.assertEqual(called, [], '非法子路径不应浪费读取 meta 与构建 artifacts')

    def test_user_config_sanitizes_non_finite_expiry_corrupt_note_and_script_svg(self):
        """user-config 必须拦截 NaN/Inf expires_at 防写出非法 JSON，清洗非字符串 note，并拦截含 <script 的 SVG。"""
        data = {
            'token': 'tok1',
            'users': {
                'u1': {
                    'password': 'pw1',
                    'status': 'active',
                    'expires_at': float('inf'),
                    'note': ['bad', 123],
                }
            },
        }
        fn = _extract_do_get({
            'data': data,
            'data_lock': threading.Lock(),
            'session_secret': 'sec',
            'meta_path': Path('/tmp/meta.json'),
            'read_meta_file': lambda p: {'server_name': 'vpn.example.com', 'public_ip': '1.2.3.4', 'listen_port': 443},
            '_active_reality_config': lambda: None,
            '_active_vmess_config': lambda: None,
            '_active_vlessenc_config': lambda: None,
            '_active_anytls_config': lambda: None,
            '_active_tuic_config': lambda: None,
            '_served_singbox_config': lambda cfg, svc: None,
            'subprocess': SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(stdout=b'<svg><script>alert(1)</script></svg>')),
        })
        h = _FakeGetHandler('/tok1/user-config?user_id=u1', authed=True)
        fn(h)
        status, payload = h.resp
        self.assertEqual(status, 200)
        # 严格 allow_nan=False 必须能正常序列化
        json.dumps(payload, allow_nan=False)
        self.assertIsNone(payload['expires_at'])
        self.assertEqual(payload['note'], '')
        self.assertEqual(payload['qr_svg'], '')

    def test_extra_link_boxes_and_user_page_html_tolerate_corrupt_inputs_and_block_script_svg(self):
        """_extra_link_boxes 须过滤非字符串标签与含 <script 的 SVG；user_page_html 须容错非字典 uinfo。"""
        out = portal._extra_link_boxes([
            (123, 'vless://bad-label', '<svg></svg>'),
            ('Reality', 'vless://ok', '<svg><script>x</script></svg>'),
        ])
        self.assertNotIn('<script>', out)
        self.assertIn('vless://ok', out)

        page = portal.user_page_html(
            'vpn.example.com', 'vpn.example.com', 443, 'QUIC', 'u1', None,
            'hysteria2://pw@vpn.example.com:443', '{}', '{}', '', 'tok1', 'k1'
        )
        self.assertIn('vpn.example.com', page)


if __name__ == '__main__':
    unittest.main()
