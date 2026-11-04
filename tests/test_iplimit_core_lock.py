"""设备上限 worker 在核心操作进行中时不重写 xray.json、不重启 Xray（2026-11-04 修）。

摘出 reality_iplimit_worker 里真实的「开启路由接口」分支执行：核心锁被别人占着时
必须跳过本轮，且不消耗 10 分钟的重试退避。
"""
import ast
import copy
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def enable_branch():
    tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
    worker = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == 'reality_iplimit_worker')
    branch = next(n for n in ast.walk(worker) if isinstance(n, ast.If)
                  and ast.unparse(n.test) == 'not ready')
    # 把 continue 包在一次性循环里执行
    loop = ast.parse('for _once in (0,):\n    pass\nelse:\n    _fell_through = True').body[0]
    loop.body = [copy.deepcopy(branch)]
    fn = ast.parse('def run():\n    pass').body[0]
    fn.body = [ast.parse('global enable_retry_at, ready, _fell_through').body[0], loop]
    return fn


class IplimitCoreLockTests(unittest.TestCase):
    def run_branch(self, core_lock, fd_error=None):
        enabled = []
        mod = mock.Mock(enable_iplimit_routing=lambda *a: enabled.append(a) or {'changed': False})
        spec = mock.Mock(loader=mock.Mock(exec_module=lambda m: None))
        env = dict(time=mock.Mock(time=time.time, sleep=lambda s: None), os=mock.Mock(),
                   importlib=mock.Mock(util=mock.Mock(spec_from_file_location=lambda *a: spec,
                                                      module_from_spec=lambda s: mod)),
                   core_operation_lock=core_lock, access_apply_lock=threading.Lock(),
                   reality_apply_lock=threading.Lock(), stats_path='x', xray_path='x', binary='b',
                   address='a', sys=sys, print=lambda *a, **k: None,
                   acquire_core_operation_lock=(mock.Mock(side_effect=fd_error) if fd_error
                                                else mock.Mock(return_value=3)),
                   enable_retry_at=0.0, ready=False, _fell_through=False)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[enable_branch()], type_ignores=[])),
                     '<branch>', 'exec'), env)
        env['run']()
        return enabled, env

    def test_skips_when_in_process_core_lock_is_held(self):
        lock = threading.Lock()
        lock.acquire()
        enabled, env = self.run_branch(lock)
        self.assertEqual(enabled, [], '核心锁被占时仍重写了 xray.json')
        self.assertEqual(env['enable_retry_at'], 0.0, '跳过的一轮消耗了重试退避')

    def test_skips_when_cross_process_lock_is_held(self):
        lock = threading.Lock()
        enabled, env = self.run_branch(lock, fd_error=RuntimeError('another core operation is running'))
        self.assertEqual(enabled, [])
        self.assertFalse(lock.locked(), '跳过时没有释放进程内核心锁')

    def test_runs_when_locks_are_free(self):
        lock = threading.Lock()
        enabled, env = self.run_branch(lock)
        self.assertEqual(len(enabled), 1)
        self.assertTrue(env['ready'])
        self.assertFalse(lock.locked())


if __name__ == '__main__':
    unittest.main()
