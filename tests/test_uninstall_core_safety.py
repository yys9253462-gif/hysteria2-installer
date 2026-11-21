"""回归测试：卸载核心必须拒绝删除宿主机自装 Xray、申领重型槽并跳过不存在的伴随单元。"""
import ast
import importlib.util
import io
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_uninst_core_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _extract_method(name, ns):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
            return ns[name]
    raise AssertionError('找不到方法: ' + name)


class UninstallCoreSafetyTests(unittest.TestCase):
    def _build_env(self, td, form_name, *, foreign=False, heavy_ok=True, states=None, enabled_map=None, stop_fail=None):
        root = Path(td)
        (root / 'etc/systemd/system').mkdir(parents=True, exist_ok=True)
        (root / 'usr/local/bin').mkdir(parents=True, exist_ok=True)
        (root / 'usr/local/bin/xray').write_bytes(b'host-xray')
        (root / 'usr/local/bin/sing-box').write_bytes(b'sing-box')
        calls = []
        states = dict(states or {'xray': 'inactive', 'hy2-anytls': 'active', 'hy2-tuic': 'inactive'})
        enabled_map = dict(enabled_map or {'xray': 'disabled', 'hy2-anytls': 'enabled', 'hy2-tuic': 'not-found'})
        stop_fail = set(stop_fail or ())

        def fake_path(value):
            text = str(value)
            if text.startswith('/'):
                return root / text.lstrip('/')
            return Path(value)

        def fake_run(args, **kwargs):
            calls.append(list(args))
            if args[:2] == ['systemctl', 'is-enabled']:
                u = args[2]
                return SimpleNamespace(returncode=0 if enabled_map.get(u) != 'not-found' else 1,
                                       stdout=enabled_map.get(u, 'not-found'))
            if args[:3] == ['systemctl', 'disable', '--now']:
                u = args[3]
                if enabled_map.get(u) == 'not-found':
                    return SimpleNamespace(returncode=1, stdout='', stderr='Unit not found')
                if u in stop_fail:
                    return SimpleNamespace(returncode=1, stdout='', stderr='stop failed')
                states[u] = 'inactive'
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if args[:2] == ['systemctl', 'disable']:
                u = args[2]
                if enabled_map.get(u) == 'not-found':
                    return SimpleNamespace(returncode=1, stdout='', stderr='Unit not found')
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if args[:2] in (['systemctl', 'start'], ['systemctl', 'restart']):
                states[args[2]] = 'active'
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        replies = []
        body = urlencode({'name': form_name}).encode()
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            _extend_deadline=Mock(return_value=heavy_ok),
            _core_users=lambda _: [],
            headers={'Content-Length': str(len(body))},
            rfile=io.BytesIO(body),
            reply_json=lambda code, payload: replies.append((code, payload)),
        )
        ns = dict(
            portal.__dict__,
            Path=fake_path,
            core_operation_lock=threading.RLock(),
            acquire_core_operation_lock=Mock(return_value=99),
            os=SimpleNamespace(close=Mock()),
            xray_unit_foreign=Mock(return_value=foreign),
            _systemd_state=lambda u: states.get(u, 'inactive'),
            subprocess=SimpleNamespace(run=fake_run),
        )
        fn = _extract_method('_h_post_uninstall_core', ns)
        fn(handler, '/tok/')
        return replies[-1], calls, root, handler

    def test_uninstall_xray_refuses_foreign_host_unit_without_deleting_binary(self):
        with tempfile.TemporaryDirectory() as td:
            (code, body), calls, root, _ = self._build_env(td, 'xray', foreign=True)
            self.assertEqual(code, 409, body)
            self.assertFalse(body['ok'])
            self.assertTrue((root / 'usr/local/bin/xray').exists(), '宿主机自装 xray 二进制被误删')
            self.assertEqual(calls, [], '拒绝卸载宿主机 xray 时不应操作 systemd')

    def test_uninstall_core_acquires_heavy_slot(self):
        with tempfile.TemporaryDirectory() as td:
            (code, body), calls, root, handler = self._build_env(td, 'xray', heavy_ok=False)
            self.assertEqual(code, 409, body)
            handler._extend_deadline.assert_called_once()
            self.assertEqual(calls, [])

    def test_uninstall_singbox_succeeds_when_tuic_unit_was_never_installed(self):
        with tempfile.TemporaryDirectory() as td:
            (code, body), calls, root, _ = self._build_env(
                td, 'sing-box',
                states={'hy2-anytls': 'active', 'hy2-tuic': 'inactive'},
                enabled_map={'hy2-anytls': 'enabled', 'hy2-tuic': 'not-found'},
            )
            self.assertEqual(code, 200, body)
            self.assertFalse((root / 'usr/local/bin/sing-box').exists())
            self.assertNotIn(['systemctl', 'disable', '--now', 'hy2-tuic'], calls)

    def test_uninstall_singbox_rollback_resets_failed_and_skips_absent_unit(self):
        with tempfile.TemporaryDirectory() as td:
            (code, body), calls, root, _ = self._build_env(
                td, 'sing-box',
                states={'hy2-anytls': 'active', 'hy2-tuic': 'inactive'},
                enabled_map={'hy2-anytls': 'enabled', 'hy2-tuic': 'not-found'},
                stop_fail={'hy2-anytls'},
            )
            self.assertEqual(code, 500, body)
            self.assertTrue((root / 'usr/local/bin/sing-box').exists())
            self.assertIn(['systemctl', 'reset-failed', 'hy2-anytls'], calls)
            self.assertIn(['systemctl', 'start', 'hy2-anytls'], calls)
            self.assertLess(
                calls.index(['systemctl', 'reset-failed', 'hy2-anytls']),
                calls.index(['systemctl', 'start', 'hy2-anytls']),
            )
            self.assertNotIn(['systemctl', 'disable', 'hy2-tuic'], calls)
            self.assertNotIn(['systemctl', 'stop', 'hy2-tuic'], calls)


if __name__ == '__main__':
    unittest.main()
