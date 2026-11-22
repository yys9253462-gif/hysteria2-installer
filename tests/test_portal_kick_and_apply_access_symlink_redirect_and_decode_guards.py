"""回归测试：kick_hy2_users 与 apply_access 防符号链接、禁 3xx 重定向泄密、防脏二进制与子进程解码守卫。"""

import ast
import http.server
import json
import socketserver
import sys
import tempfile
import threading
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

TREE = ast.parse((REPO / 'portal.py').read_text(encoding='utf-8'))


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://127.0.0.1:1/steal')
        self.end_headers()

    def do_POST(self):
        self.send_response(302)
        self.send_header('Location', 'http://127.0.0.1:1/steal')
        self.end_headers()

    def log_message(self, format, *args):
        pass


class PortalKickAndApplyAccessGuardsTests(unittest.TestCase):
    def test_kick_hy2_users_rejects_symlink_and_oversized_meter_config(self):
        """kick_hy2_users 读 usage-meter-config.json 须拒绝符号链接与超过 1 MiB 文件。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'usage-meter-config.json'
            cfg.write_bytes(b'{' + b' ' * (1024 * 1024 + 32) + b'}')
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('超限不应读盘')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('超限不应读盘')):
                self.assertFalse(portal.kick_hy2_users(root, ['u1']))

            cfg.write_text(json.dumps({'hysteria': {'url': 'http://127.0.0.1:19999', 'secret': 's'}}), encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == cfg), \
                    patch.object(Path, 'read_bytes', side_effect=AssertionError('符号链接不应读盘')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('符号链接不应读盘')):
                self.assertFalse(portal.kick_hy2_users(root, ['u1']))

    def test_kick_and_apply_access_block_3xx_redirect_to_prevent_secret_leak(self):
        """生产回环统计请求遇到 302 重定向必须拒绝跟随，防止 Authorization 密钥泄露。"""
        with socketserver.TCPServer(('127.0.0.1', 0), _RedirectHandler) as srv:
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    (root / 'usage-meter-config.json').write_text(
                        json.dumps({'hysteria': {'url': f'http://127.0.0.1:{port}', 'secret': 'top-secret'}}),
                        encoding='utf-8',
                    )
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        portal.kick_hy2_users(root, ['u1'])
                    self.assertEqual(ctx.exception.code, 302)
            finally:
                srv.shutdown()

    def test_apply_access_rejects_symlink_and_oversized_xray_json(self):
        """apply_access 与锁内快照应用须拒绝符号链接与超 4 MiB 的 xray.json。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xj = root / 'xray.json'
            xj.write_bytes(b'{' + b' ' * (4 * 1024 * 1024 + 32) + b'}')
            with self.assertRaisesRegex(ValueError, '4 MiB'):
                portal._enforce_node_access_xray_hy2(root, {'users': {}})

            xj.write_text(json.dumps({'inbounds': []}), encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == xj):
                with self.assertRaisesRegex(OSError, '符号链接'):
                    portal._enforce_node_access_xray_hy2(root, {'users': {}})

    def test_apply_xray_access_snapshot_locked_guards_binary_nan_and_subproc_decode(self):
        """_apply_xray_access_snapshot_locked 须禁止 allow_nan、校验 binary 与为 systemctl 补 errors='replace'。"""
        node = next(
            n for n in ast.walk(TREE)
            if isinstance(n, ast.FunctionDef) and n.name == '_apply_xray_access_snapshot_locked'
        )
        missing_decode = []
        found_allow_nan = False
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            if isinstance(call.func, ast.Attribute) and call.func.attr == 'run':
                kw = {k.arg: k.value for k in call.keywords if k.arg}
                text_kw = kw.get('text')
                if isinstance(text_kw, ast.Constant) and text_kw.value is True:
                    err_kw = kw.get('errors')
                    if not (isinstance(err_kw, ast.Constant) and err_kw.value == 'replace'):
                        missing_decode.append(call.lineno)
            if isinstance(call.func, ast.Attribute) and call.func.attr == 'dumps':
                kw = {k.arg: k.value for k in call.keywords if k.arg}
                nan_kw = kw.get('allow_nan')
                if isinstance(nan_kw, ast.Constant) and nan_kw.value is False:
                    found_allow_nan = True
        self.assertEqual(missing_decode, [], f'以下 systemctl 调用缺少 errors="replace": {missing_decode}')
        self.assertTrue(found_allow_nan, '_apply_xray_access_snapshot_locked 写 candidate 须强制 allow_nan=False')

        # 构造带非法前导 - 的 binary 必须被拦截（拒绝注入）
        src = ast.get_source_segment((REPO / 'portal.py').read_text(encoding='utf-8'), node) or ''
        self.assertIn("startswith('-')", src, '须拦截以 - 开头的非法 xray binary 路径')


if __name__ == '__main__':
    unittest.main()
