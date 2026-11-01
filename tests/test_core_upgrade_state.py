"""core_upgrade 被改成非字典时，门户仍要能启动，升级接口也不能 500。

startup 段旧写法 `(data.get('core_upgrade') or {}).get('state')`：值是 7 或
字符串时抛 AttributeError，门户进程直接退出 —— 而门户同时是 Hysteria 的
鉴权后端，它起不来等于所有用户都连不上。
"""
import ast
import copy
import json
import tempfile
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def startup_statements():
    """Extract the persistent startup recovery helper."""
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                and n.name == 'persist_interrupted_core_job')
    return [copy.deepcopy(node)]


def upgrade_status_branch():
    return next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and any(isinstance(c, ast.Constant) and c.value == 'upgrade-status'
                        for c in n.test.comparators))


class CoreUpgradeStateTests(unittest.TestCase):
    MISSING = object()

    def run_startup(self, value):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'portal.json'
            data = {} if value is self.MISSING else {'core_upgrade': copy.deepcopy(value)}
            path.write_text(json.dumps(data), encoding='utf-8')
            data = json.loads(path.read_text(encoding='utf-8'))
            env = {'data': data, 'Path': Path, 'portal_state_file_lock':
                   lambda *_: __import__('contextlib').nullcontext(),
                   'atomic_write_private': lambda file_path, payload:
                       Path(file_path).write_bytes(payload), 'json': json}
            exec(compile(ast.fix_missing_locations(
                ast.Module(body=startup_statements(), type_ignores=[])), '<startup>', 'exec'), env)
            env['persist_interrupted_core_job'](path, data)
            return env['data'], json.loads(path.read_text(encoding='utf-8'))

    def test_corrupt_state_does_not_block_startup(self):
        for bad in (None, 7, 'x', ['a'], True):
            with self.subTest(bad=bad):
                memory, disk = self.run_startup(bad)
                self.assertNotIn('core_upgrade', memory)
                self.assertNotIn('core_upgrade', disk)

    def test_missing_state_is_left_alone(self):
        memory, disk = self.run_startup(self.MISSING)
        self.assertNotIn('core_upgrade', memory)
        self.assertNotIn('core_upgrade', disk)

    def test_running_job_is_marked_interrupted(self):
        memory, disk = self.run_startup({'state': 'running', 'started_at': 1})
        self.assertEqual(memory['core_upgrade']['state'], 'interrupted')
        self.assertEqual(disk['core_upgrade']['state'], 'interrupted')
        self.assertEqual(disk['core_upgrade']['started_at'], 1)
        self.assertIn('error', disk['core_upgrade'])

    def test_completed_job_is_preserved(self):
        memory, disk = self.run_startup({'state': 'completed', 'tag': 'v2'})
        self.assertEqual(memory['core_upgrade'], {'state': 'completed', 'tag': 'v2'})
        self.assertEqual(disk['core_upgrade'], {'state': 'completed', 'tag': 'v2'})

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
