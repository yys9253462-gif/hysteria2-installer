"""解锁检测同一时刻只跑一轮，后来者 429（2026-11-04 修）。

每轮十几个并发外连；重叠请求各占一个 quick 槽，只会互相拖慢、占满槽位。
摘出真实的 _h_api_unlock_check，用慢的 run_unlock_checks 桩并发调用两次。
"""
import ast
import copy
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def load_handler(env):
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
              and n.name == '_h_api_unlock_check')
    exec(compile(ast.Module(body=[copy.deepcopy(fn)], type_ignores=[]), '<unlock>', 'exec'), env)
    return env['_h_api_unlock_check']


class UnlockCheckSingleFlightTest(unittest.TestCase):
    def test_overlapping_requests_are_refused(self):
        def slow_checks():
            time.sleep(0.5)
            return [{'name': 'x', 'ok': True}]
        env = {'unlock_check_lock': threading.Lock(), 'run_unlock_checks': slow_checks, 'time': time}
        handler = load_handler(env)
        statuses = []
        def call():
            h = SimpleNamespace(_extend_deadline=lambda *a, **k: True,
                                reply_json=lambda status, payload: statuses.append(status))
            handler(h)
        threads = [threading.Thread(target=call) for _ in range(2)]
        for t in threads:
            t.start()
            time.sleep(0.1)
        for t in threads:
            t.join()
        self.assertEqual(sorted(statuses), [200, 429])
        # 锁在结束后释放：下一轮照常可以跑。
        call()
        self.assertEqual(statuses[-1], 200)


if __name__ == '__main__':
    unittest.main()
