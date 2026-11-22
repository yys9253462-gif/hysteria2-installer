"""回归测试：全仓所有 POST 处理函数统一拒绝重复、全角、带符号与负 Content-Length 且不读取请求体。"""

import ast
import email.message
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)

TARGET_HANDLERS = (
    '_h_post_do_upgrade_impl',
    '_h_post_manage_proxy',
    '_h_post_install_amneziawg',
    '_h_post_manage_amneziawg',
    '_h_post_manage_reality',
    '_h_post_manage_vmess',
    '_h_post_install_core',
    '_h_post_uninstall_core',
    '_h_post_manage_anytls',
    '_h_post_manage_tuic',
    '_h_post_manage_vlessenc',
    '_h_post_login',
)


def _extract_method(name):
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(PORTAL_SRC, node)
            dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
            ns = {}
            exec(dedented, ns)
            return ns[name]
    raise AssertionError(f'未找到方法 {name}')


class _SpyRfile:
    def __init__(self):
        self.called = False

    def read(self, n=-1):
        self.called = True
        return b''


class AllPostHandlersStrictContentLengthGuardsTests(unittest.TestCase):
    def test_no_bare_int_content_length_left_in_portal(self):
        """portal.py 中不得残留任何裸 int(self.headers.get('Content-Length', ...)) 解析。"""
        self.assertNotIn("int(self.headers.get('Content-Length'", PORTAL_SRC)

    def test_all_twelve_remaining_post_handlers_reject_duplicate_fullwidth_and_signed_cl(self):
        """剩余 12 个 POST 处理函数面对重复/全角/带符号 Content-Length 均须返回 400 且绝不读 rfile。"""
        dup_headers = email.message.Message()
        dup_headers.add_header('Content-Length', '10')
        dup_headers.add_header('Content-Length', '20')
        bad_header_cases = [
            ('duplicate', dup_headers),
            ('fullwidth', {'Content-Length': '１０'}),
            ('plus-sign', {'Content-Length': '+10'}),
            ('negative', {'Content-Length': '-1'}),
        ]
        for name in TARGET_HANDLERS:
            fn = _extract_method(name)
            for label, hdrs in bad_header_cases:
                rfile = _SpyRfile()
                resp = []
                h = SimpleNamespace(
                    headers=hdrs,
                    rfile=rfile,
                    is_authenticated=lambda: True,
                    reply=lambda code, body, *a, **kw: (resp.append(code) or (code, body)),
                    reply_json=lambda code, payload: (resp.append(code) or (code, payload)),
                )
                fn(h, '/tok/')
                self.assertEqual(resp, [400], f'{name} 面对 {label} Content-Length 应返回 400，实际 {resp}')
                self.assertFalse(rfile.called, f'{name} 面对 {label} Content-Length 不得读取 rfile')


if __name__ == '__main__':
    unittest.main()
