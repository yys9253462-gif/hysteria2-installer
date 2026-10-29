"""损坏的 traffic_suspend 不能阻止节点停用，也不能把 units 字符串当服务名。

真实后果：主控制台判定整机超额后调用 node/suspend，节点里 traffic_suspend
被写成 7 或字符串时 `dict(...)` 抛 TypeError/ValueError → 500，服务一台都
没停，用户继续超量使用；units 被写成字符串时逐字符 systemctl stop，
既停不掉服务又留下错误的停用记录。
"""
import ast
import copy
from pathlib import Path
import re
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
NAMES = {'suspend_state', 'unit_suspended'}


def load():
    # suspend_state 在模块级；unit_suspended 是 serve() 内的闭包。
    body = [copy.deepcopy(n) for n in TREE.body
            if isinstance(n, ast.FunctionDef) and n.name == 'suspend_state']
    unit = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
                and n.name == 'unit_suspended')
    unit = copy.deepcopy(unit)
    env = {'re': re}
    pattern = next(n for n in TREE.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'TRAFFIC_SUSPEND_UNIT_RE'
                           for t in n.targets))
    exec(compile(ast.Module(body=[copy.deepcopy(pattern)], type_ignores=[]),
                 '<suspend-re>', 'exec'), env)
    exec(compile(ast.fix_missing_locations(ast.Module(body=body + [unit], type_ignores=[])),
                 '<suspend>', 'exec'), env)
    return env


class TrafficSuspendStateTests(unittest.TestCase):
    def test_corrupt_state_is_treated_as_not_suspended(self):
        env = load()
        for bad in (None, 7, 'broken', ['x'], {'suspended': 'yes'}, {'suspended': 1}):
            with self.subTest(bad=bad):
                self.assertEqual(env['suspend_state']({'traffic_suspend': bad}), {})

    def test_units_must_be_a_list_of_names(self):
        env = load()
        state = env['suspend_state'](
            {'traffic_suspend': {'suspended': True, 'units': 'hysteria-server'}})
        self.assertEqual(state.get('units'), [])
        state = env['suspend_state'](
            {'traffic_suspend': {'suspended': True,
                                 'units': ['hysteria-server', 'xray', 7, None, '']}})
        self.assertEqual(state.get('units'), ['hysteria-server', 'xray'])

    def test_healthy_state_survives_round_trip(self):
        env = load()
        good = {'suspended': True, 'units': ['hysteria-server'], 'since': 123}
        self.assertEqual(env['suspend_state']({'traffic_suspend': good}), good)

    def test_unit_suspended_never_raises_on_corrupt_state(self):
        env = load()
        data = {'traffic_suspend': {'suspended': True, 'units': ['xray']}}
        env.update(data=data, data_lock=threading.RLock())
        self.assertTrue(env['unit_suspended']('xray'))
        self.assertFalse(env['unit_suspended']('x'))
        env['data'] = {'traffic_suspend': {'suspended': True, 'units': 'xray'}}
        self.assertFalse(env['unit_suspended']('x'))


if __name__ == '__main__':
    unittest.main()
