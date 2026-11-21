"""回归测试：同一处理器实例连续处理多次 HEAD 请求时必须每次都写出状态行与响应头。"""
import ast
import io
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _extract_do_head():
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'do_HEAD':
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            ns = {}
            exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
            return ns['do_HEAD']
    raise AssertionError('找不到 do_HEAD 方法')


class _FakeHandler:
    do_HEAD = _extract_do_head()

    def __init__(self):
        self.wfile = io.BytesIO()

    def end_headers(self):
        self.wfile.write(b'\r\n')

    def do_GET(self):
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n')
        self.end_headers()
        self.wfile.write(b'hello')


class HeadKeepAliveReuseTests(unittest.TestCase):
    def test_consecutive_head_requests_on_same_handler_both_emit_headers_only(self):
        handler = _FakeHandler()

        handler.do_HEAD()
        first = handler.wfile.getvalue()
        self.assertEqual(first, b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n')

        handler.wfile = io.BytesIO()
        handler.do_HEAD()
        second = handler.wfile.getvalue()
        self.assertEqual(second, b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n')


if __name__ == '__main__':
    unittest.main()
