"""回归测试：_h_post_install_core / _h_post_uninstall_core 先校验参数再申领重型槽，且卸载回滚隔离单单元超时。"""

import ast
import copy
import io
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_handler(name, extra_env):
    tree = ast.parse(PORTAL.read_text(encoding='utf-8'))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    env.update(extra_env)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'), env)
    return env[name]


class CoreInstallUninstallHardeningTests(unittest.TestCase):
    def test_invalid_core_name_or_negative_length_does_not_claim_heavy_slot(self):
        for fn_name in ('_h_post_install_core', '_h_post_uninstall_core'):
            fn = _extract_handler(fn_name, {})
            claimed = []

            class FakeHandler:
                def __init__(self, body, cl=None):
                    self.headers = {'Content-Length': str(len(body) if cl is None else cl)}
                    self.rfile = io.BytesIO(body)

                def is_authenticated(self):
                    return True

                def _extend_deadline(self, seconds, heavy=False):
                    claimed.append((seconds, heavy))
                    return True

                def reply_json(self, status, payload):
                    return status, payload

            status, payload = fn(FakeHandler(b'name=unknown'), '/tok/')
            self.assertEqual(status, 400, fn_name)
            self.assertEqual(claimed, [], f'{fn_name} 非法核心名却先申领了重型槽')

            status2, _ = fn(FakeHandler(b'name=xray', cl=-1), '/tok/')
            self.assertEqual(status2, 400, fn_name)
            self.assertEqual(claimed, [], f'{fn_name} 负 Content-Length 却先申领了重型槽')

    def test_uninstall_core_rollback_continues_after_first_unit_timeout(self):
        restored_starts = []

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0, stdout='enabled\n', stderr='')
            if cmd[:3] == ['systemctl', 'disable', '--now']:
                if cmd[3] == 'hy2-tuic':
                    return SimpleNamespace(returncode=1, stdout='', stderr='failed')
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            if cmd[:2] == ['systemctl', 'enable'] and cmd[2] == 'hy2-anytls':
                raise subprocess.TimeoutExpired(cmd, 30)
            if cmd[:2] == ['systemctl', 'start']:
                restored_starts.append(cmd[2])
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        state_calls = {'hy2-tuic': 0}

        def fake_state(unit):
            if unit == 'hy2-tuic':
                state_calls['hy2-tuic'] += 1
                return 'active'
            return 'active'

        fn = _extract_handler('_h_post_uninstall_core', {
            'core_operation_lock': threading.Lock(),
            'acquire_core_operation_lock': lambda: 99,
            'os': SimpleNamespace(close=lambda fd: None),
            'subprocess': SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
            '_systemd_state': fake_state,
            '_service_stop_confirmed': lambda res, st: res.returncode == 0,
            'ANYTLS_SERVICE': 'hy2-anytls',
            'TUIC_SERVICE': 'hy2-tuic',
            'ANYTLS_BINARY': '/usr/local/bin/sing-box',
        })

        class FakeHandler:
            headers = {'Content-Length': str(len(b'name=sing-box'))}
            rfile = io.BytesIO(b'name=sing-box')

            def is_authenticated(self):
                return True

            def _extend_deadline(self, seconds, heavy=False):
                return True

            def _core_users(self, name):
                return []

            def reply_json(self, status, payload):
                return status, payload

        status, payload = fn(FakeHandler(), '/tok/')
        self.assertEqual(status, 500)
        self.assertIn('hy2-anytls', payload['error'])
        self.assertIn('hy2-tuic', restored_starts, '首个单元回滚超时后跳过了第二个单元恢复')


if __name__ == '__main__':
    unittest.main()
