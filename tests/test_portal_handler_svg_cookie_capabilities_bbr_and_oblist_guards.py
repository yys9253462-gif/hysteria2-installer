"""回归测试：Handler 的 SVG 安全校验、登录/登出 Cookie 路径注入防护、capabilities 与 bbr-status/ob_list 的读盘上限/符号链接/编码/注释与脏字段守卫。"""

import ast
import copy
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


class TestPortalHandlerSvgCookieCapabilitiesBbrAndOblistGuards(unittest.TestCase):
    def test_is_safe_svg_payload_rejects_xss_vectors_and_accepts_clean_svg(self):
        """_is_safe_svg_payload 应接受干净 SVG，并拒绝 script/foreignObject/javascript:/事件处理器与超大体积。"""
        fn = getattr(portal, '_is_safe_svg_payload', None)
        self.assertIsNotNone(fn, 'portal.py 必须提供模块级 _is_safe_svg_payload 校验函数')

        clean = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>'
        self.assertTrue(fn(clean))
        self.assertTrue(fn(clean.decode('utf-8')))

        bad_samples = [
            b'',
            b'not svg at all',
            b'<svg><script>alert(1)</script></svg>',
            b'<svg><foreignObject><body>hi</body></foreignObject></svg>',
            b'<svg><a href="javascript:alert(1)">x</a></svg>',
            b'<svg onload="alert(1)"></svg>',
            b'<svg><image href="x" onerror = "alert(1)"/></svg>',
            b'<svg>' + b'a' * (2 * 1024 * 1024 + 10) + b'</svg>',
            None,
            123,
        ]
        for sample in bad_samples:
            self.assertFalse(fn(sample), f'应拒绝非法 SVG: {str(sample)[:60]!r}')

    def test_safe_cookie_path_token_blocks_crlf_and_semicolon_injection(self):
        """_safe_cookie_path_token 必须剔除分号、空白、CRLF 等注入字符，且登录/登出均通过它构造 Set-Cookie。"""
        fn = getattr(portal, '_safe_cookie_path_token', None)
        self.assertIsNotNone(fn, 'portal.py 必须提供 _safe_cookie_path_token')

        self.assertEqual(fn('abc_123-XYZ.1'), '/abc_123-XYZ.1/')
        self.assertEqual(fn('tok; Domain=evil.com\r\nSet-Cookie: a=1'), '/tokDomainevil.comSet-Cookiea1/')
        self.assertEqual(fn('   ;;;\r\n'), '/')
        self.assertEqual(fn(None), '/')

        # 确认登录和登出两处 Set-Cookie 均调用了 _safe_cookie_path_token
        self.assertGreaterEqual(SRC.count('_safe_cookie_path_token('), 3,
                                '除定义外，登录与登出两处 Set-Cookie 都必须使用 _safe_cookie_path_token')

    def test_svg_endpoints_all_use_is_safe_svg_payload(self):
        """用户 qr.svg、用户页内嵌 qr_svg、awg-qr.svg、管理员 qr.svg 均必须调用 _is_safe_svg_payload。"""
        self.assertGreaterEqual(SRC.count('_is_safe_svg_payload('), 5,
                                '定义外四处 SVG 响应/内嵌分支均必须调用 _is_safe_svg_payload')

    def test_capabilities_version_parser_strips_inline_comment(self):
        """/api/v1/capabilities 的 PORTAL_VERSION 解析必须正确剥离行内注释且保持无额外依赖。"""
        start = SRC.index("if sub == 'capabilities':")
        anchor = SRC.index("portal_version =", start)
        anchor = SRC.rfind('\n', 0, anchor) + 1
        end = SRC.index("return self.reply_json(200, {", anchor)
        block = SRC[anchor:end]
        lines = block.splitlines()
        indent = min(len(ln) - len(ln.lstrip()) for ln in lines if ln.strip())
        dedented = '\n'.join(ln[indent:] if len(ln) >= indent else ln for ln in lines)

        with tempfile.TemporaryDirectory() as td:
            fake_portal = Path(td) / 'portal.py'
            fake_portal.write_bytes(b"PORTAL_VERSION = '2.99'  # \xb0\xb1 inline comment\n")
            ns = {
                'Path': Path,
                '__file__': str(fake_portal),
                'PORTAL_VERSION': '2.00',
            }
            exec(compile(dedented, '<cap_ver>', 'exec'), ns)
            self.assertEqual(ns['portal_version'], '2.99')

    def test_capabilities_xray_read_and_subprocesses_hardened(self):
        """/api/v1/capabilities 必须使用受限读盘、字典校验，且 _svc_active/_bbr_now 使用 UTF-8 替换解码。"""
        start = SRC.index("if sub == 'capabilities':")
        end = SRC.index("if sub.startswith('users/get/'):", start)
        block = SRC[start:end]

        self.assertIn('lstat()', block, 'capabilities 读 xray.json 必须用 lstat() 拒符号链接并检查体积')
        self.assertIn('isinstance(_xcfg, dict)', block, 'capabilities 必须校验 xray.json 顶层为 dict')
        self.assertGreaterEqual(block.count("errors='replace'"), 3,
                                'capabilities 的 _svc_active、_bbr_now 与文件读取都必须指定 errors=\'replace\'')

    def test_bbr_status_and_ob_list_guards(self):
        """_h_get_bbr_status 与 _ob_list 必须对 sysctl/读盘加编码、常规文件/体积上限，并过滤非字符串 bbr_target_version。"""
        bbr_start = SRC.index("def _h_get_bbr_status(self, subpath):")
        bbr_end = SRC.index("def _ob_list(self):", bbr_start)
        bbr_block = SRC[bbr_start:bbr_end]

        self.assertIn("errors='replace'", bbr_block, '_h_get_bbr_status 的 _sysctl_read 与配置读取必须加 errors=\'replace\'')
        self.assertIn('lstat()', bbr_block, '_h_get_bbr_status 读 99-bbr.conf 必须检查符号链接与体积上限')
        self.assertIn('isinstance(raw_target_ver, str)', bbr_block, '_h_get_bbr_status 必须过滤非字符串 bbr_target_version')

        ob_start = bbr_end
        ob_end = SRC.index("return self.reply_json(200, {", ob_start)
        ob_block = SRC[ob_start:ob_end]
        self.assertIn('lstat()', ob_block, '_ob_list 读 config.yaml 必须检查符号链接与体积上限')


if __name__ == '__main__':
    unittest.main()
