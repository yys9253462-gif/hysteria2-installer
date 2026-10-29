"""损坏的 data['users'] 不能让 /auth 直接掐断连接（客户端只会无限重试）。"""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def helpers():
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'user_table')
    env = {}
    exec(compile(ast.Module(body=[ast.parse(ast.unparse(node)).body[0]], type_ignores=[]),
                 '<user-table>', 'exec'), env)
    return env


class UserTableTests(unittest.TestCase):
    def test_corrupt_containers_become_empty_table(self):
        env = helpers()
        for bad in (None, ['broken'], 'oops', 7, True):
            with self.subTest(bad=bad):
                self.assertEqual(env['user_table']({'users': bad}), {})
        self.assertEqual(env['user_table']({}), {})
        self.assertEqual(env['user_table'](None), {})

    def test_healthy_table_is_returned_unchanged(self):
        env = helpers()
        users = {'u': {'password': 'p'}}
        self.assertIs(env['user_table']({'users': users}), users)


if __name__ == '__main__':
    unittest.main()
