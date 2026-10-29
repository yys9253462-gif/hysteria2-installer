"""core_upgrade 被改成非字典时，门户仍要能启动，升级接口也不能 500。

startup 段旧写法 `(data.get('core_upgrade') or {}).get('state')`：值是 7 或
字符串时抛 AttributeError，门户进程直接退出 —— 而门户同时是 Hysteria 的
鉴权后端，它起不来等于所有用户都连不上。
"""
import ast
import copy
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def startup_statements():
    """serve() 里紧跟在 `_core_job = ...` 之后的几条语句。"""
    serve = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    start = next(i for i, node in enumerate(serve.body)
                 if isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == '_core_job'
                         for t in node.targets))
    statements = []
    for node in serve.body[start:]:
        statements.append(copy.deepcopy(node))
        # pop 写在 `elif` 里，是 If 节点的一部分，不是独立语句。
        if (isinstance(node, ast.If) and len(statements) > 1
                and any(isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Attribute)
                        and inner.func.attr == 'pop' for inner in ast.walk(node))):
            break
    return statements


def upgrade_status_branch():
    return next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and any(isinstance(c, ast.Constant) and c.value == 'upgrade-status'
                        for c in n.test.comparators))


class CoreUpgradeStateTests(unittest.TestCase):
    MISSING = object()

    def run_startup(self, value):
        data = {} if value is self.MISSING else {'core_upgrade': copy.deepcopy(value)}
        env = {'data': data}
        exec(compile(ast.fix_missing_locations(
            ast.Module(body=startup_statements(), type_ignores=[])), '<startup>', 'exec'), env)
        return env['data']

    def test_corrupt_state_does_not_block_startup(self):
        for bad in (None, 7, 'x', ['a'], True):
            with self.subTest(bad=bad):
                self.assertNotIn('core_upgrade', self.run_startup(bad))

    def test_missing_state_is_left_alone(self):
        self.assertNotIn('core_upgrade', self.run_startup(self.MISSING))

    def test_running_job_is_marked_interrupted(self):
        data = self.run_startup({'state': 'running', 'started_at': 1})
        self.assertEqual(data['core_upgrade']['state'], 'interrupted')
        self.assertEqual(data['core_upgrade']['started_at'], 1)
        self.assertIn('error', data['core_upgrade'])

    def test_completed_job_is_preserved(self):
        data = self.run_startup({'state': 'completed', 'tag': 'v2'})
        self.assertEqual(data['core_upgrade'], {'state': 'completed', 'tag': 'v2'})

    def test_upgrade_status_endpoint_handles_corrupt_state(self):
        branch = upgrade_status_branch()
        env = {'data': {'core_upgrade': 7}, 'data_lock': threading.RLock()}
        fn = ast.parse('def status(self):\n    pass').body[0]
        fn.body = copy.deepcopy(branch.body)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     '<status-fn>', 'exec'), env)

        class Handler:
            def is_authenticated(self):
                return True

            def reply_json(self, code, payload):
                return code, payload

        code, payload = env['status'](Handler())
        self.assertEqual(code, 200)
        self.assertEqual(payload['job'], {})


if __name__ == '__main__':
    unittest.main()
