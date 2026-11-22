"""回归测试：全门户残余 6 处 POST Content-Length 5000 位 DoS 清零、全部 9 处 qrencode SVG XSS/_is_safe_svg_payload 覆盖与坏字节容错、及 _apply_tuic_enable 端口校验。"""

import ast
import io
import json
import re
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import portal

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


def _extract_handler_method(name, extra_ns=None):
    tree = ast.parse(PORTAL_SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = textwrap.dedent(ast.get_source_segment(PORTAL_SRC, node))
            ns = {
                'json': json,
                're': re,
                'Path': Path,
                'subprocess': subprocess,
                'parse_qs': __import__('urllib.parse', fromlist=['parse_qs']).parse_qs,
                '_is_safe_svg_payload': portal._is_safe_svg_payload,
                '_valid_port': portal._valid_port,
                '_log_ignored': lambda *a, **k: None,
                'MASTER_USER_ID': portal.MASTER_USER_ID,
                'QUOTA_RANGE_ERROR': portal.QUOTA_RANGE_ERROR,
            }
            if extra_ns:
                ns.update(extra_ns)
            exec(compile(src, f'<{name}>', 'exec'), ns)
            return ns[name]
    raise AssertionError(f'portal.py 未找到方法 {name}')


class _FakeHeaders(dict):
    def get_all(self, key):
        return [self[key]] if key in self else []


class _DummyHandler:
    def __init__(self, cl_value):
        self.headers = _FakeHeaders({'Content-Length': cl_value})
        self.rfile = io.BytesIO(b'')
        self.replies = []

    def is_authenticated(self):
        return True

    def reply_json(self, code, payload):
        self.replies.append((code, payload))
        return code, payload

    def reply(self, code, body, mime='text/plain'):
        self.replies.append((code, body))
        return code, body


class TestPortalRemainingClDosSvgXssAndTuicPortGuards(unittest.TestCase):
    def test_every_content_length_parse_has_digit_length_cap(self):
        """portal.py 全文件所有 int(_raw_cl_s) 前必须存在 len(_raw_cl_s) 上限检查，无任何遗漏。"""
        lines = PORTAL_SRC.splitlines()
        missing = []
        for idx, line in enumerate(lines, 1):
            if 'int(_raw_cl_s)' in line:
                window = '\n'.join(lines[max(0, idx - 6):idx])
                if 'len(_raw_cl_s)' not in window:
                    missing.append(f'L{idx}: {line.strip()}')
        self.assertEqual(missing, [], f'以下 Content-Length 解析缺少位数上限守卫: {missing}')

    def test_six_remaining_post_handlers_return_413_on_5000_digit_content_length(self):
        """残余 6 处 POST 入口遇到 5000 位 Content-Length 必须直接返回 413，不得因 int() 4300 位限制报 500/400。"""
        huge_cl = '9' * 5000
        for name in (
            '_h_post_manage_proxy',
            '_h_post_manage_anytls',
            '_h_post_manage_tuic',
            '_h_post_manage_user',
            '_h_post_login',
        ):
            fn = _extract_handler_method(name)
            h = _DummyHandler(huge_cl)
            fn(h, '/tok/')
            self.assertEqual(h.replies[0][0], 413, f'{name} 遇到 5000 位 Content-Length 应返回 413，实际: {h.replies}')

        fn_bbr = _extract_handler_method('_set_bbr_locked')
        h_bbr = _DummyHandler(huge_cl)
        fn_bbr(h_bbr)
        self.assertEqual(h_bbr.replies[0][0], 413, f'_set_bbr_locked 遇到 5000 位 Content-Length 应返回 413，实际: {h_bbr.replies}')

    def test_every_qrencode_site_uses_is_safe_svg_payload(self):
        """portal.py 全文件每一处 qrencode SVG 出口必须经过 _is_safe_svg_payload 校验。"""
        lines = PORTAL_SRC.splitlines()
        missing = []
        for idx, line in enumerate(lines, 1):
            if "'qrencode'" in line:
                window = '\n'.join(lines[idx - 1:min(len(lines), idx + 22)])
                if '_is_safe_svg_payload' not in window:
                    missing.append(f'L{idx}: {line.strip()}')
        self.assertEqual(missing, [], f'以下 qrencode 出口缺少 _is_safe_svg_payload 守卫: {missing}')

    def test_qr_svg_for_blocks_xss_vectors_and_handles_bad_utf8(self):
        """qr_svg_for 必须拦截 foreignObject / onload / javascript: 等 XSS 载体。"""
        for bad in (
            b'<svg><foreignObject><body onload="alert(1)"/></foreignObject></svg>',
            b'<svg onload="alert(1)"></svg>',
            b'<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
        ):
            fake = subprocess.CompletedProcess(['qrencode'], 0, stdout=bad, stderr=b'')
            with mock.patch.object(portal.subprocess, 'run', return_value=fake):
                self.assertIsNone(portal.qr_svg_for('hysteria2://ok'), f'应拦截恶意 SVG: {bad!r}')

        good = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>'
        fake_ok = subprocess.CompletedProcess(['qrencode'], 0, stdout=good, stderr=b'')
        with mock.patch.object(portal.subprocess, 'run', return_value=fake_ok):
            self.assertEqual(portal.qr_svg_for('hysteria2://ok'), good.decode('utf-8'))

    def test_status_handlers_block_foreignobject_and_survive_invalid_utf8_qr(self):
        """_h_get_anytls_status / _h_get_tuic_status 遇到 foreignObject 应清空 qr_svg，遇到坏 UTF-8 不抛异常。"""
        for name, cfg_fn, svc_const in (
            ('_h_get_anytls_status', '_active_anytls_config', 'ANYTLS_SERVICE'),
            ('_h_get_tuic_status', '_active_tuic_config', 'TUIC_SERVICE'),
        ):
            evil = subprocess.CompletedProcess(
                ['qrencode'], 0,
                stdout=b'<svg><foreignObject><script>1</script></foreignObject></svg>',
                stderr=b'',
            )
            bad_utf8 = subprocess.CompletedProcess(
                ['qrencode'], 0,
                stdout=b'<svg>\xff</svg>',
                stderr=b'',
            )
            extra = {
                cfg_fn: lambda: {'domain': 'ex.com', 'sni': 'ex.com', 'port': 4433, 'secret': 's'},
                svc_const: 'hy2-test',
                '_systemd_state': lambda svc: 'active',
                '_singbox_version': lambda: (1, 12, 0),
                'anytls_uri_for_user': lambda *a, **k: 'anytls://ok',
                'tuic_uri_for_user': lambda *a, **k: 'tuic://ok',
            }
            fn = _extract_handler_method(name, extra)
            for proc, expect_empty in ((evil, True), (bad_utf8, False)):
                h = _DummyHandler('0')
                h._extend_deadline = lambda *a, **k: None
                with mock.patch.object(subprocess, 'run', return_value=proc):
                    fn(h, 'status')
                code, payload = h.replies[0]
                self.assertEqual(code, 200)
                if expect_empty:
                    self.assertEqual(payload['config']['qr_svg'], '', f'{name} 未拦截 foreignObject SVG')
                else:
                    self.assertIn('<svg>', payload['config']['qr_svg'], f'{name} 遇坏 UTF-8 应替换解码而非崩溃')

    def test_apply_tuic_enable_uses_valid_port_for_blocked_listen_port(self):
        """_apply_tuic_enable 不得对 listen_port 裸调 int(value)，应走 _valid_port 防 bool/超长串污染。"""
        tree = ast.parse(PORTAL_SRC)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == '_apply_tuic_enable':
                src = ast.get_source_segment(PORTAL_SRC, node)
                self.assertNotIn('blocked.add(int(value))', src)
                self.assertIn('_valid_port', src)
                return
        self.fail('未找到 _apply_tuic_enable')


if __name__ == '__main__':
    unittest.main()
