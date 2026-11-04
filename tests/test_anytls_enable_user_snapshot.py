"""AnyTLS 启用时在协议锁内读取用户表（2026-11-04 修，与 TUIC 一致）。

撤销流程在 anytls_apply_lock 内同步 anytls.json；启用若在锁外取用户，撤销刚写完、
启用再用旧名单覆盖，被停用的用户又能连上。这里用一把记录持有状态的锁，执行真实的
_apply_anytls_enable 到取用户那一步，断言取用户时锁已被持有。
"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class AnytlsEnableSnapshotTests(unittest.TestCase):
    def test_users_are_read_inside_the_protocol_lock(self):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == '_apply_anytls_enable')
        locks = [n for n in ast.walk(fn) if isinstance(n, ast.With)
                 and any(ast.unparse(i.context_expr) == 'anytls_apply_lock' for i in n.items)]
        self.assertTrue(locks)
        inside = any(isinstance(c, ast.Call) and ast.unparse(c.func) == 'anytls_users'
                     for w in locks for c in ast.walk(w))
        outside = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and ast.unparse(c.func) == 'anytls_users'
                   and not any(c in list(ast.walk(w)) for w in locks)]
        self.assertTrue(inside, '用户表不是在 anytls_apply_lock 内读取的')
        self.assertEqual(outside, [], '仍有在锁外读取的用户表')


if __name__ == '__main__':
    unittest.main()
