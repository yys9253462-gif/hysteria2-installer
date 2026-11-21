"""回归测试：AnyTLS / TUIC 启停失败回滚使用原子私有写入并在停用回滚时持有协议锁。"""
import ast
import contextlib
import importlib.util
import io
import os
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_proto_rb_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _find_method(name):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError('找不到方法: ' + name)


def _extract_method(name, ns):
    node = _find_method(name)
    mod = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(mod)
    code = compile(mod, str(ROOT / 'portal.py'), 'exec')
    exec(code, ns)
    return ns[name]


class _TrackingLock:
    def __init__(self):
        self._lock = threading.RLock()
        self.depth = 0

    def __enter__(self):
        self._lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        self.depth -= 1
        self._lock.release()


class ProtocolRollbackSafetyTests(unittest.TestCase):
    def test_four_protocol_handlers_use_atomic_restore_instead_of_write_bytes(self):
        for name in (
            '_apply_anytls_enable',
            '_h_post_manage_anytls',
            '_apply_tuic_enable',
            '_h_post_manage_tuic',
        ):
            fn = _find_method(name)
            src = ast.unparse(fn)
            self.assertIn('_restore_config_atomically', src, f'{name} 未使用原子私有恢复函数')
            self.assertNotIn('cfg_path.write_bytes', src, f'{name} 仍在使用裸 cfg_path.write_bytes')

    def test_anytls_and_tuic_disable_rollback_hold_protocol_lock_and_preserve_0600(self):
        cases = [
            ('_h_post_manage_anytls', 'anytls_apply_lock', 'anytls_config',
             portal.ANYTLS_CONFIG_NAME, portal.ANYTLS_SERVICE, '_active_anytls_config'),
            ('_h_post_manage_tuic', 'tuic_apply_lock', 'tuic_config',
             portal.TUIC_CONFIG_NAME, portal.TUIC_SERVICE, '_active_tuic_config'),
        ]
        for method_name, lock_name, cfg_key, cfg_file, svc_name, active_fn in cases:
            with self.subTest(method=method_name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg_path = root / cfg_file
                original = b'{"inbounds":[{"users":[{"password":"fake-secret-only"}]}]}'
                cfg_path.write_bytes(original)
                if os.name == 'posix':
                    cfg_path.chmod(0o600)

                lock = _TrackingLock()
                observed = {'restore_file_locked': None, 'restore_svc_locked': None}
                real_restore = portal._restore_config_atomically

                def spy_restore_file(path, data):
                    observed['restore_file_locked'] = lock.depth > 0
                    return real_restore(path, data)

                def spy_restore_svc(unit, snap):
                    observed['restore_svc_locked'] = lock.depth > 0
                    return True

                data = {cfg_key: {'enabled': True, 'port': 44555, 'domain': 'demo.example.com', 'secret': 'fake-sec'}}
                ns = dict(
                    portal.__dict__,
                    data=data,
                    data_lock=threading.RLock(),
                    core_operation_lock=threading.RLock(),
                    core_operation_file_lock=lambda: contextlib.nullcontext(),
                    portal_path=root / 'portal.json',
                    save_data=Mock(side_effect=OSError('disk full')),
                    regenerate_page=Mock(),
                    close_protocol_port=Mock(return_value=True),
                    _restore_config_atomically=spy_restore_file,
                    _restore_systemd_service_state=spy_restore_svc,
                    _systemd_service_snapshot=Mock(return_value={'active': 'active', 'enabled': 'enabled'}),
                    _systemd_state=Mock(return_value='inactive'),
                    _service_stop_confirmed=Mock(return_value=True),
                    subprocess=SimpleNamespace(
                        run=Mock(return_value=SimpleNamespace(returncode=0, stdout='', stderr='')),
                        SubprocessError=subprocess.SubprocessError,
                    ),
                )
                ns[lock_name] = lock
                ns[active_fn] = lambda: data[cfg_key]

                replies = []
                body = b'action=disable'
                handler = SimpleNamespace(
                    is_authenticated=lambda: True,
                    headers={'Content-Length': str(len(body))},
                    rfile=io.BytesIO(body),
                    reply_json=lambda code, payload: replies.append((code, payload)),
                )
                fn = _extract_method(method_name, ns)
                fn(handler, '/tok/')

                self.assertEqual(replies[-1][0], 500)
                self.assertEqual(cfg_path.read_bytes(), original)
                self.assertTrue(observed['restore_file_locked'], f'{method_name} 停用回滚写配置未持有 {lock_name}')
                self.assertTrue(observed['restore_svc_locked'], f'{method_name} 停用回滚恢复服务未持有 {lock_name}')
                if os.name == 'posix':
                    mode = stat.S_IMODE(cfg_path.stat().st_mode)
                    self.assertEqual(mode, 0o600)


if __name__ == '__main__':
    unittest.main()
