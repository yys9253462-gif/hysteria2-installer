"""proxy_services 容器或单条记录损坏时，gost 配置生成与增删不能整体失败。

旧行为：`for ... in data.get('proxy_services', [])` 在容器是 null/str/int 时抛
TypeError，`svc.get(...)` 在条目是字符串时抛 AttributeError，端口写成 "abc"
时抛 ValueError —— 都被 reload_gost 吞成 `False`，界面只显示
「GOST 配置未成功应用」，新增代理永久失败。
"""
import ast
import copy
import json
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def load_writer():
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
              and n.name == 'write_gost_config')
    helper = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                  and n.name == 'proxy_services')
    root = Path(__file__).resolve().parents[1] / 'tests' / '_gost_fixture'
    env = {}
    exec(compile(ast.Module(body=[copy.deepcopy(helper), copy.deepcopy(fn)], type_ignores=[]),
                 '<gost>', 'exec'), env)
    return env


class GostConfigCorruptStateTests(unittest.TestCase):
    def test_corrupt_entries_are_skipped_not_fatal(self):
        for bad in (None, 'x', 7, [None], ['x'], [7], [{'port': 'abc'}],
                    [{'port': True}], [{'port': None}], [{'port': -1}],
                    [{'port': 70000}], [{'type': None, 'port': 7000}]):
            with self.subTest(bad=bad):
                import tempfile
                root = Path(tempfile.mkdtemp())
                written = {}
                env = load_writer()
                env.update({'data': {'proxy_services': bad}, 'data_lock': threading.RLock(),
                            'portal_path': root / 'portal.json', 'json': json,
                            'atomic_write_private': lambda p, b: written.update(
                                path=p, payload=b)})
                env['write_gost_config']()
                self.assertIn('path', written)
                cfg = json.loads(written['payload'])
                # 损坏条目一律跳过；合法端口必须保留。
                ports = [s['addr'] for s in cfg['services']]
                self.assertNotIn(':-1', ports)
                self.assertNotIn(':70000', ports)

    def test_valid_entries_still_written(self):
        import tempfile
        from unittest.mock import patch
        root = Path(tempfile.mkdtemp())
        written = {}
        env = load_writer()
        env.update({'data': {'proxy_services': [
            {'type': 'socks5', 'port': 25001, 'username': 'u', 'password': 'p'},
            {'type': 'http', 'port': 25002, 'username': 'u2', 'password': 'p2'},
            'broken']},
            'data_lock': threading.RLock(), 'portal_path': root / 'portal.json',
            'json': json,
            'atomic_write_private': lambda p, b: written.update(payload=b)})
        env['write_gost_config']()
        cfg = json.loads(written['payload'])
        self.assertEqual([s['addr'] for s in cfg['services']], [':25001', ':25002'])
        self.assertEqual(cfg['services'][0]['handler']['type'], 'socks5')
        self.assertEqual(cfg['services'][1]['handler']['type'], 'http')


if __name__ == '__main__':
    unittest.main()
