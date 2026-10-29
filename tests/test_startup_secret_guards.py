"""portal.json 的会话密钥字段损坏时，门户启动行为必须明确。

serve() 顶部用 `session_secret` 给会话 Cookie 签名。旧写法
`data.get('session_secret') or data['auth_hash']` 直接拿它当字符串用：
被写成数字/None 时 hmac 抛异常，门户进程退出 —— 而它同时是 Hysteria 的
鉴权后端，等于全节点用户都连不上；反过来也不能悄悄替机主换掉 auth_hash
（那会让现有登录凭据静默失效）。
"""
import ast
import copy
import hashlib
from pathlib import Path
import secrets
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def startup_statements():
    serve = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    start = next(i for i, node in enumerate(serve.body)
                 if isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == '_required' for t in node.targets))
    keep = []
    for node in serve.body[start:]:
        keep.append(copy.deepcopy(node))
        # 到 session_secret 的兜底块为止；再往后会引入线程与锁，
        # 与本测试无关。
        if (isinstance(node, ast.If) and 'session_secret' in ast.unparse(node.test)
                and any(isinstance(inner, ast.Assign) for inner in node.body)):
            break
    return keep


class StartupSecretGuardTests(unittest.TestCase):
    def run_startup(self, **fields):
        data = {'port': 1, 'token': 't', 'auth_hash': 'a' * 64, 'users': {}}
        data.update(fields)
        for name in [k for k, v in fields.items() if v is ...]:
            data.pop(name)
        env = {'data': data, 'hashlib': hashlib, 'secrets': secrets, 'json': __import__('json'),
               'Path': Path, 'time': __import__('time'), 'os': __import__('os'),
               'sys': __import__('sys'),
               'atomic_write_private': lambda *a, **k: None,
               'portal_path': Path('/nonexistent/portal.json')}
        exec(compile(ast.fix_missing_locations(
            ast.Module(body=startup_statements(), type_ignores=[])), '<serve-start>', 'exec'), env)
        return env['data']

    def test_missing_required_field_still_fails_loudly(self):
        with self.assertRaises(SystemExit):
            self.run_startup(**{'port': ...})

    def test_corrupt_auth_hash_is_reported_not_silently_replaced(self):
        for bad in (..., 0, '', None, 12345):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit) as caught:
                    self.run_startup(**{'auth_hash': bad})
                self.assertIn('auth_hash', str(caught.exception))

    def test_corrupt_session_secret_is_replaced_not_fatal(self):
        for bad in (..., 0, '', None, 12345, ['x']):
            with self.subTest(bad=bad):
                data = self.run_startup(**{'session_secret': bad})
                self.assertIsInstance(data['session_secret'], str)
                self.assertTrue(data['session_secret'])

    def test_healthy_values_pass_through(self):
        data = self.run_startup(session_secret='given-secret')
        self.assertEqual(data['session_secret'], 'given-secret')
        self.assertEqual(data['auth_hash'], 'a' * 64)


if __name__ == '__main__':
    unittest.main()
