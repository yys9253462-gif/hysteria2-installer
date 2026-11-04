"""运行中门户保存时不能盖掉 adopt / refresh 刚写的键（2026-11-04 修）。

install.sh 先跑 portal.py adopt（写入新 api_key / auth_hash / 机主密码），再 restart
门户；旧进程 SIGTERM 时 save_data 用旧内存整份覆盖，控制台随即 401。
"""
import ast
import contextlib
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class PortalSaveKeepsCliWritesTests(unittest.TestCase):
    def _save_data(self, data, path, digest):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        nodes = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in ('save_data', '_prepare_save_payload')]
        env = {'data': data, 'data_lock': threading.RLock(), 'json': json, 'hashlib': hashlib,
               'portal_path': path, 'atomic_write_private': portal.atomic_write_private,
               'portal_state_file_lock': lambda *_: contextlib.nullcontext(), 'contextlib': contextlib,
               'disk_state': {'digest': digest}, 'merge_cli_owned_state': portal.merge_cli_owned_state}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<save>', 'exec'), env)
        return env

    def test_out_of_band_adopt_survives_shutdown_save(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'portal.json'
            old = {'api_key': 'old', 'auth_hash': 'h1', 'session_epoch': 1,
                   'users': {portal.MASTER_USER_ID: {'password': 'p1'}, 'buyer': {'used_bytes': 9}}}
            raw = json.dumps(old).encode()
            mem = json.loads(raw)
            mem['users']['buyer']['used_bytes'] = 50  # 运行中门户自己的新用量
            new = json.loads(raw)
            new.update(api_key='new', auth_hash='h2', session_epoch=2)
            new['users'][portal.MASTER_USER_ID]['password'] = 'p2'
            path.write_text(json.dumps(new), encoding='utf-8')
            env = self._save_data(mem, path, hashlib.sha256(raw).digest())
            env['save_data']()
            after = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(after['api_key'], 'new')
            self.assertEqual(after['auth_hash'], 'h2')
            self.assertEqual(after['session_epoch'], 2)
            self.assertEqual(after['users'][portal.MASTER_USER_ID]['password'], 'p2')
            self.assertEqual(after['users']['buyer']['used_bytes'], 50)

    def test_own_writes_are_not_reverted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'portal.json'
            mem = {'api_key': 'a', 'users': {}}
            raw = json.dumps(mem).encode()
            path.write_bytes(raw)
            env = self._save_data(mem, path, hashlib.sha256(raw).digest())
            env['save_data']()
            mem['api_key'] = 'rotated-in-process'
            env['save_data']()
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['api_key'], 'rotated-in-process')

    def test_disk_write_does_not_hold_data_lock(self):
        """写盘 / fsync 期间别的线程能拿到 data_lock（2026-11-04 修，/auth 不再被慢盘卡住）。"""
        import threading
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'portal.json'
            mem = {'users': {}}
            path.write_bytes(json.dumps(mem).encode())
            env = self._save_data(mem, path, hashlib.sha256(path.read_bytes()).digest())
            lock = env['data_lock']
            seen = []

            def slow_write(p, payload):
                t = threading.Thread(target=lambda: seen.append(lock.acquire(timeout=2) and (lock.release() or True)))
                t.start(); t.join()
                Path(p).write_bytes(payload)
            env['atomic_write_private'] = slow_write
            env['save_data']()
        self.assertEqual(seen, [True], '写盘期间 data_lock 仍被占着')


if __name__ == '__main__':
    unittest.main()
