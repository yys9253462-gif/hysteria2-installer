"""回归测试：出站回滚写 config.yaml 与门户自愈写 client_meta.json 均走原子私有落盘。"""
import ast
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_atomic_cfg_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _find_func(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError('找不到函数: ' + name)


class AtomicPrivateConfigWritesTests(unittest.TestCase):
    def test_target_functions_do_not_use_bare_write_text(self):
        for name in ('_rollback_outbounds', 'sync_cert_trust', 'sync_pin', 'prepare'):
            src = ast.unparse(_find_func(name))
            self.assertIn('atomic_write_private', src, f'{name} 未使用 atomic_write_private')
            self.assertNotIn('.write_text(', src, f'{name} 仍在使用非原子 write_text')

    def test_rollback_outbounds_uses_atomic_write_private_and_sets_0600(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\n', encoding='utf-8')
            if os.name == 'posix':
                cfg.chmod(0o644)
            original = 'listen: :443\nobfs:\n  type: salamander\n'
            called = []
            real_awp = portal.atomic_write_private

            def spy_awp(path, payload):
                called.append((Path(path), payload))
                return real_awp(path, payload)

            with patch.object(portal, 'atomic_write_private', side_effect=spy_awp), \
                 patch.object(portal, '_restart_hy2'), \
                 patch.object(portal.subprocess, 'run',
                              return_value=SimpleNamespace(returncode=0, stdout='active')):
                state = portal._rollback_outbounds(cfg, original)

            self.assertEqual(state, 'active')
            self.assertEqual(len(called), 1)
            self.assertEqual(called[0][0], cfg)
            self.assertEqual(cfg.read_text(encoding='utf-8'), original)
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(cfg.stat().st_mode), 0o600)

    def test_sync_pin_writes_meta_via_atomic_write_private(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta_path = root / 'client_meta.json'
            meta = {'is_insecure': False, 'server_name': 'demo.example.com', 'pin_sha256': 'a' * 64}
            meta_path.write_text(json.dumps(meta), encoding='utf-8')
            if os.name == 'posix':
                meta_path.chmod(0o644)
            called = []
            real_awp = portal.atomic_write_private

            def spy_awp(path, payload):
                called.append(Path(path))
                return real_awp(path, payload)

            with patch.object(portal, 'atomic_write_private', side_effect=spy_awp):
                portal.sync_pin(meta, root, meta_path)

            self.assertEqual(called, [meta_path])
            saved = json.loads(meta_path.read_text(encoding='utf-8'))
            self.assertEqual(saved['pin_sha256'], '')
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(meta_path.stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
