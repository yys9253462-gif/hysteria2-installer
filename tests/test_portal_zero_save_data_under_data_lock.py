"""回归测试：全 portal.py 不变量——严禁在 with data_lock 锁内调用 save_data() 等阻塞落盘操作，防止慢盘 fsync 阻塞全节点 /auth。"""

import ast
import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


class PortalZeroSaveDataUnderDataLockTests(unittest.TestCase):
    def test_no_save_data_or_blocking_io_called_inside_data_lock(self):
        """整个 portal.py 除 save_data 自身外，不得在任何 with data_lock 块内调用 save_data/subprocess.run/urlopen/regenerate_page。"""
        violations = []

        class _Visitor(ast.NodeVisitor):
            def __init__(self):
                self.lock_depth = 0
                self.fn_stack = []

            def visit_FunctionDef(self, node):
                self.fn_stack.append(node.name)
                self.generic_visit(node)
                self.fn_stack.pop()

            def visit_With(self, node):
                is_data_lock = any(
                    isinstance(item.context_expr, ast.Name) and item.context_expr.id == 'data_lock'
                    for item in node.items
                )
                if is_data_lock:
                    self.lock_depth += 1
                self.generic_visit(node)
                if is_data_lock:
                    self.lock_depth -= 1

            def visit_Call(self, node):
                if self.lock_depth > 0:
                    name = ''
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        name = node.func.attr
                    if name in ('save_data', 'run', 'Popen', 'urlopen', 'regenerate_page', 'sleep', 'apply_egress_config'):
                        fn = self.fn_stack[-1] if self.fn_stack else '<module>'
                        if fn != 'save_data':
                            violations.append(f'L{node.lineno} [{fn}]: {name}()')
                self.generic_visit(node)

        _Visitor().visit(TREE)
        self.assertEqual(violations, [], f'发现仍在 data_lock 锁内执行的阻塞调用：{violations}')


if __name__ == '__main__':
    unittest.main()
