"""协议配置段被改坏时，启用流程里读端口 / ws_path 不抛异常（2026-11-06 修）。

摘出 _apply_vlessenc_enable 里组装 blocked_ports 的那条赋值与 _vmess_ws_path 执行，
reality_config / vmess_config 写成字符串或列表。
"""
import ast
import copy
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


class ProtocolSectionReadTests(unittest.TestCase):
    BAD = {'reality_config': 'x', 'vmess_config': [1]}

    def test_vlessenc_blocked_ports_survive_corrupt_sections(self):
        fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == '_apply_vlessenc_enable')
        assign = next(n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'blocked_ports' for t in n.targets))
        env = dict(portal.__dict__, data=dict(self.BAD), m={'listen_port': 443, 'subscription_port': 8443})
        exec(compile(ast.Module(body=[copy.deepcopy(assign)], type_ignores=[]), '<blocked>', 'exec'), env)
        self.assertEqual(env['blocked_ports'], {443, 8443, None})

    def test_vmess_ws_path_survives_corrupt_section(self):
        fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == '_vmess_ws_path')
        env = dict(portal.__dict__, data=dict(self.BAD), data_lock=threading.RLock())
        exec(compile(ast.Module(body=[copy.deepcopy(fn)], type_ignores=[]), '<ws>', 'exec'), env)
        args = [None] * len(fn.args.args)
        path = env['_vmess_ws_path'](*args)
        self.assertRegex(path, r'^/[A-Za-z0-9_\-]{8,48}$')


if __name__ == '__main__':
    unittest.main()
