"""/traffic-speed 遇到损坏的速率样本必须继续出数，不能每 2 秒 500。

速率样本是内存态字典，由采样线程写入、由这个接口读取。旧格式（列表）
或半截元组会让 `sample[0]` 的减法抛 TypeError，控制台首页实时流量整块空白，
而节点与鉴权完全正常 —— 这类「只有控制台坏了」最难排查。
"""
import ast
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _real_safe_int(_probe=None):
    """从 portal.py 里取出真实的 _safe_int，供隔离命名空间使用。

    🔴 不要在测试里另写一份等价实现：一旦两份语义漂移（比如真实版本
    接受 "5" 而桩拒绝），测试就不再证明生产行为 —— 而这条守卫正是
    为了「坏数据不能让 /traffic-speed 500」。
    """
    node = next(n for n in ast.walk(TREE)
                if isinstance(n, ast.FunctionDef) and n.name == '_safe_int')
    mod = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(mod)
    env = {}
    exec(compile(mod, '<safe_int>', 'exec'), env)
    return env['_safe_int']


def load(tracker, data, summaries=None):
    funcs = [n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
             and n.name in {'_meter_speed_sample', '_h_get_traffic_speed'}]
    env = {'time': time, 'data_lock': threading.RLock(), 'speed_tracker': tracker,
           'SPEED_WINDOW_SECONDS': 15, 'data': data,
           # 2026-10-31：_h_get_traffic_speed 现在用 _safe_int 兜住
           # used_bytes 的 "12.5"/null/列表（否则 sum() 直接 TypeError，
           # 前端主轮询整块 500）。用生产实现，不要在这里另写一份 ——
           # 两份语义一旦漂移，测试就不再证明真实行为。
           '_safe_int': _real_safe_int(),
           'user_table': lambda d: d.get('users') if isinstance(d.get('users'), dict) else {},
           'users_list_rows': lambda users: list(users.items())
           if isinstance(users, dict) else [],
           'usage_hot_summary': summaries or (lambda uid: {
               'measured_bytes': None, 'measurement_ok': False,
               'measurement_started_at': None, 'measurement_scope': 'unavailable'})}
    exec(compile(ast.Module(body=funcs, type_ignores=[]), '<speed>', 'exec'), env)
    return env


class SpeedTrackerRobustnessTests(unittest.TestCase):
    def call(self, env):
        class Handler:
            def is_authenticated(self):
                return True

            def reply_json(self, code, payload):
                return code, payload

        return env['_h_get_traffic_speed'](Handler(), '')

    def test_corrupt_tracker_values_are_dropped(self):
        data = {'users': {'u': {'used_bytes': 0}}}
        for tracker in ({'u': 'bad'}, {'u': ['bad']},
                        {'u': {'hysteria': 'bad'}},
                        {'u': {'hysteria': (0.0,)}},
                        {'u': {'hysteria': (0.0, 1, 2, 'extra')}}):
            with self.subTest(tracker=tracker):
                env = load(tracker, data)
                with patch.object(time, 'monotonic', return_value=100):
                    status, body = self.call(env)
                self.assertEqual(status, 200)
                self.assertEqual(body['users']['u']['tx'], 0)
                self.assertEqual(body['users']['u']['rx'], 0)
                self.assertEqual(env['speed_tracker']['u']
                                 if 'u' in env['speed_tracker'] else {}, {})

    def test_valid_samples_still_summed(self):
        # 样本存的是「每秒字节数」（_meter_speed_sample 里除以 elapsed），
        # 两个来源的速率相加就是该用户当前速度。
        now = 100.0
        tracker = {'u': {'hysteria': (now - 1, 1048576, 0),
                         'reality': (now - 1, 0, 2097152)}}
        env = load(tracker, {'users': {'u': {'used_bytes': 3}}})
        with patch.object(time, 'monotonic', return_value=now):
            status, body = self.call(env)
        self.assertEqual(status, 200)
        self.assertAlmostEqual(body['users']['u']['tx'], 1048576)
        self.assertAlmostEqual(body['users']['u']['rx'], 2097152)
        self.assertAlmostEqual(body['node_tx'], 1048576)
        self.assertAlmostEqual(body['node_rx'], 2097152)
        self.assertEqual(body['users']['u']['used_bytes'], 3)

    def test_non_dict_tracker_is_read_as_empty_without_replacement(self):
        data = {'users': {'u': {'used_bytes': 0}}}
        for tracker in (None, ['bad'], 'oops', 7):
            with self.subTest(tracker=tracker):
                env = load(tracker, data)
                # load() 会把非 dict 直接塞进模块变量，但生产里该变量由
                # 闭包持有；这里让它保持原值，断言接口不崩也不改写它。
                status, body = self.call(env)
                self.assertEqual(status, 200)
                self.assertEqual(body['users']['u']['tx'], 0)

    def test_expired_samples_are_removed(self):
        env = load({'u': {'hysteria': (0.0, 5, 5)}}, {'users': {'u': {'used_bytes': 0}}})
        with patch.object(time, 'monotonic', return_value=100):
            status, body = self.call(env)
        self.assertEqual(status, 200)
        self.assertNotIn('u', env['speed_tracker'])


if __name__ == '__main__':
    unittest.main()
