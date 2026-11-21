import ast
import copy
import io
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs

REPO = Path(__file__).resolve().parent.parent
PORTAL_PATH = REPO / 'portal.py'
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

TREE = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))


def _extract_method(name, extra_env):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeHandler:
    def __init__(self, body=b'', events=None):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.events = events if events is not None else []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.events.append(('deadline', seconds, heavy))
        return True

    def _core_users(self, name):
        return []

    def reply_json(self, status, payload):
        return status, payload


class TestUninstallCoreTimeoutAndDomainGuards(unittest.TestCase):
    def test_uninstall_core_rolls_back_on_disable_timeout_and_isolates_reset_failed(self):
        """停止第二个单元时 systemctl disable --now 超时，必须触发回滚恢复第一个单元，且 reset-failed 超时不阻断 start。"""
        calls = []
        unit_active = {portal.ANYTLS_SERVICE: True, portal.TUIC_SERVICE: True}

        def fake_state(u):
            return 'active' if unit_active.get(u) else 'inactive'

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0, stdout='enabled\n', stderr='')
            if cmd[:3] == ['systemctl', 'disable', '--now']:
                if cmd[3] == portal.ANYTLS_SERVICE:
                    unit_active[portal.ANYTLS_SERVICE] = False
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                raise subprocess.TimeoutExpired(cmd, 30)
            if cmd[:2] == ['systemctl', 'reset-failed']:
                raise subprocess.TimeoutExpired(cmd, 5)
            if cmd[:2] == ['systemctl', 'start']:
                unit_active[cmd[2]] = True
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with tempfile.TemporaryDirectory() as td:
            lock_f = Path(td) / 'core.lock'
            fn = _extract_method('_h_post_uninstall_core', {
                'core_operation_lock': threading.Lock(),
                'acquire_core_operation_lock': lambda: portal.os.open(str(lock_f), portal.os.O_CREAT | portal.os.O_RDWR),
                'xray_unit_foreign': lambda: False,
                '_systemd_state': fake_state,
                'subprocess': SimpleNamespace(
                    run=fake_run,
                    TimeoutExpired=subprocess.TimeoutExpired,
                    SubprocessError=subprocess.SubprocessError,
                ),
            })
            st, body = fn(_FakeHandler(b'name=sing-box'), '/tok/')

        self.assertEqual(st, 500)
        self.assertIn('已恢复原服务状态', body['error'])
        self.assertTrue(unit_active[portal.ANYTLS_SERVICE], '第一个已被停掉的单元未在回滚中重启恢复')
        self.assertIn(['systemctl', 'start', portal.ANYTLS_SERVICE], calls)

    def test_uninstall_core_still_removes_binary_if_daemon_reload_times_out(self):
        """卸载收尾阶段 daemon-reload / reset-failed 超时时，不得跳过删除目标二进制文件。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            fake_bin = td_path / 'sing-box'
            fake_bin.write_bytes(b'bin')
            lock_f = td_path / 'core.lock'

            def fake_run(cmd, **kwargs):
                if cmd[:2] == ['systemctl', 'is-enabled']:
                    return SimpleNamespace(returncode=1, stdout='not-found\n', stderr='')
                if cmd[:2] in (['systemctl', 'daemon-reload'], ['systemctl', 'reset-failed']):
                    raise subprocess.TimeoutExpired(cmd, 30)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            fn = _extract_method('_h_post_uninstall_core', {
                'core_operation_lock': threading.Lock(),
                'acquire_core_operation_lock': lambda: portal.os.open(str(lock_f), portal.os.O_CREAT | portal.os.O_RDWR),
                'ANYTLS_BINARY': str(fake_bin),
                'xray_unit_foreign': lambda: False,
                '_systemd_state': lambda u: 'inactive',
                'subprocess': SimpleNamespace(
                    run=fake_run,
                    TimeoutExpired=subprocess.TimeoutExpired,
                    SubprocessError=subprocess.SubprocessError,
                ),
            })
            st, body = fn(_FakeHandler(b'name=sing-box'), '/tok/')
            self.assertEqual(st, 200, body)
            self.assertFalse(fake_bin.exists(), 'daemon-reload 超时不应阻止删除已卸载的核心二进制')

    def test_cores_status_extends_deadline_and_protocol_enables_handle_non_string_server_name(self):
        """_h_get_cores_status 须先续期死线，且四大域名协议启用遇到非字符串 server_name 须返回可读 RuntimeError。"""
        events = []
        fn_status = _extract_method('_h_get_cores_status', {
            '_singbox_version': lambda: None,
            '_systemd_state': lambda u: 'inactive',
            'awg_installed': lambda: False,
            'AWG_SVC_NAME': 'amneziawg-server',
            'Path': lambda p: SimpleNamespace(exists=lambda: False),
        })
        st, body = fn_status(_FakeHandler(events=events), 'cores-status')
        self.assertEqual(st, 200)
        self.assertTrue(any(ev[0] == 'deadline' for ev in events), f'_h_get_cores_status 未续期连接死线: {events}')

        for fn_name in ('_apply_anytls_enable', '_apply_tuic_enable'):
            fn_en = _extract_method(fn_name, {
                'read_meta_file': lambda p: {'server_name': 12345},
                'meta_path': Path('/tmp/meta.json'),
            })
            with self.assertRaisesRegex(RuntimeError, '需要先绑定域名'):
                fn_en(SimpleNamespace())


if __name__ == '__main__':
    unittest.main()
