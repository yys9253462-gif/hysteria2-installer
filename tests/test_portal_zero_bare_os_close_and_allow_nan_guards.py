"""回归测试：全 portal.py 清零裸 os.close 异常掩盖与最后 4 处漏写 allow_nan=False 的 json.dumps。"""

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _catches_oserror(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    t = handler.type
    names = []
    if isinstance(t, ast.Name):
        names.append(t.id)
    elif isinstance(t, ast.Tuple):
        for elt in t.elts:
            if isinstance(elt, ast.Name):
                names.append(elt.id)
    return any(n in ('OSError', 'Exception', 'BaseException') for n in names)


class PortalZeroBareOsCloseAndAllowNanGuardsTests(unittest.TestCase):
    def test_all_json_dumps_in_portal_enforce_allow_nan_false(self):
        """portal.py 中全部 json.dumps 调用均须显式指定 allow_nan=False。"""
        missing = []
        for node in ast.walk(TREE):
            if not isinstance(node, ast.Call):
                continue
            if (isinstance(node.func, ast.Attribute) and node.func.attr == 'dumps'
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'json'):
                kw = {k.arg: k.value for k in node.keywords if k.arg}
                nan_kw = kw.get('allow_nan')
                if not (isinstance(nan_kw, ast.Constant) and nan_kw.value is False):
                    missing.append(node.lineno)
        self.assertEqual(missing, [], f'以下 json.dumps 缺少 allow_nan=False: {missing}')

    def test_all_os_close_calls_in_portal_are_guarded_against_oserror(self):
        """portal.py 中全部 os.close() 调用均须位于捕获 OSError 的 try 块内，防止清理时掩盖主异常。"""
        bare = []

        def _walk(node, in_guarded_try=False):
            if isinstance(node, ast.Try):
                catches = any(_catches_oserror(h) for h in node.handlers)
                for stmt in node.body:
                    _walk(stmt, in_guarded_try or catches)
                for h in node.handlers:
                    for stmt in h.body:
                        _walk(stmt, in_guarded_try)
                for stmt in node.orelse:
                    _walk(stmt, in_guarded_try)
                for stmt in node.finalbody:
                    _walk(stmt, in_guarded_try)
                return
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and node.func.attr == 'close'
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os'):
                    if not in_guarded_try:
                        bare.append(node.lineno)
            for child in ast.iter_child_nodes(node):
                _walk(child, in_guarded_try)

        _walk(TREE, False)
        self.assertEqual(bare, [], f'以下 os.close() 未被捕获 OSError 的 try 块隔离: {bare}')

    def test_core_operation_file_lock_preserves_body_error_when_os_close_fails(self):
        """core_operation_file_lock 退出时若 os.close 抛 OSError，不得掩盖锁内业务异常。"""
        with tempfile.TemporaryDirectory() as td:
            lock_file = Path(td) / 'core.lock'
            real_close = os.close

            def _failing_close(fd):
                try:
                    real_close(fd)
                finally:
                    raise OSError('simulated close failure')

            with patch.dict(os.environ, {'HY2_CORE_OPERATION_LOCK': str(lock_file)}), \
                    patch.object(portal.os, 'close', side_effect=_failing_close):
                with self.assertRaisesRegex(RuntimeError, 'inner-boom'):
                    with portal.core_operation_file_lock():
                        raise RuntimeError('inner-boom')


if __name__ == '__main__':
    unittest.main()
