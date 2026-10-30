"""AWG 的 meta / peers 文件被改坏时，/awg-state 仍要返回可用结构。

这两个 JSON 由 awgctl.sh 写入，也可能被手工编辑或截断。
旧写法 `...get('peers', [])` 后直接 len()/p.get()：peers 是字符串或含非 dict
条目时抛异常，整个端点 500，面板的 AWG 卡片整块空白 —— 看起来像「AWG 没装」。
"""
import ast
import copy
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
META = object()
PEERS = object()


def load():
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
              and n.name == 'awg_state')
    env = {'AWG_META_PATH': META, 'AWG_PEERS_PATH': PEERS, 'AWG_CTL': '/nonexistent',
           'AWG_CONF_PATH': '/nonexistent', 'AWG_GO_PATH': '/nonexistent',
           'awg_installed': lambda: False, 'awg_active': lambda: False, 'Path': Path}
    exec(compile(ast.Module(body=[copy.deepcopy(fn)], type_ignores=[]),
                 '<awg-state>', 'exec'), env)
    return env


def run(meta, peers):
    env = load()
    env['awg_read_json'] = lambda path, default: (
        meta if path is META else (peers if path is PEERS else default))
    return env['awg_state']()


class AwgStateRobustnessTests(unittest.TestCase):
    def test_corrupt_peers_do_not_raise(self):
        for bad in ({'peers': 'x'}, {'peers': 7}, {'peers': [None]},
                    {'peers': ['x']}, {'peers': {'a': 1}}, 'oops', 7, None):
            with self.subTest(bad=bad):
                state = run({}, bad)
                self.assertTrue(state['ok'])
                self.assertEqual(state['peer_count'], 0)
                self.assertEqual(state['peers'], [])

    def test_valid_peers_are_kept_and_corrupt_entries_skipped(self):
        state = run({}, {'peers': [None, 'x', {'name': 'ok', 'address': '10.0.0.2'}]})
        self.assertEqual(state['peer_count'], 1)
        self.assertEqual(state['peers'][0]['name'], 'ok')

    def test_corrupt_meta_falls_back_to_defaults(self):
        for bad in (7, 'x', [None], None):
            with self.subTest(bad=bad):
                state = run(bad, {'peers': []})
                self.assertEqual(state['line'], '3')
                self.assertEqual(state['port'], '')
                self.assertEqual(state['endpoint'], '')

    def test_healthy_meta_round_trips(self):
        state = run({'line': '2', 'port': 2408, 'endpoint': 'example.com:2408'},
                    {'peers': [{'name': 'p1'}]})
        self.assertEqual((state['line'], state['port'], state['endpoint']),
                         ('2', '2408', 'example.com:2408'))
        self.assertEqual(state['peer_count'], 1)


if __name__ == '__main__':
    unittest.main()
