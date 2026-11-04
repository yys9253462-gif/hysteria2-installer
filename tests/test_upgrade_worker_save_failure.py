"""核心更新 worker 结果落盘失败时不死线程，内存里的结果照样可读（2026-11-04 修）。

从处理函数里摘出真实的 upgrade_worker 闭包执行。
"""
import ast
import copy
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def worker_fn(env):
    tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'upgrade_worker')
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])),
                 '<upgrade-worker>', 'exec'), env)
    return env['upgrade_worker']


class UpgradeWorkerSaveFailureTests(unittest.TestCase):
    def test_save_failure_keeps_result_and_does_not_raise(self):
        data = {'core_upgrade': {'state': 'running'}}

        def save():
            raise OSError('disk full')
        env = {'data': data, 'data_lock': threading.RLock(), 'time': time, 'sys': sys,
               '_core_ver_cache': {'t': 1.0}, 'allow_custom': False, 'save_data': save,
               'AtomicWriteDurabilityError': portal.AtomicWriteDurabilityError,
               'upgrade_core_binary': lambda allow_custom=False: {'version': 'v2.9'}}
        worker_fn(env)()   # 旧实现在这里抛 OSError
        self.assertEqual(data['core_upgrade']['state'], 'completed')


if __name__ == '__main__':
    unittest.main()
