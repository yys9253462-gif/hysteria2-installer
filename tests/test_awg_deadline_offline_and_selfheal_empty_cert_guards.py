import ast
import copy
import io
import json
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
    env['awg_endpoint_error'] = lambda ep: ''
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeHandler:
    def __init__(self, body, events=None, heavy_ok=True):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.events = events if events is not None else []
        self.heavy_ok = heavy_ok

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.events.append(('deadline', seconds, heavy))
        return self.heavy_ok

    def reply_json(self, status, payload):
        return status, payload


class TestAwgDeadlineOfflineAndSelfhealEmptyCertGuards(unittest.TestCase):
    def test_install_awg_rejects_fullwidth_port_strips_leading_zero_and_extends_deadline_first(self):
        """_h_post_install_amneziawg 须拦截全角端口、去前导零，并在 ensure_awgctl 之前申请重型死线。"""
        events = []
        awg_args = []
        fn = _extract_method('_h_post_install_amneziawg', {
            'unit_suspended': lambda u: False,
            'AWG_SVC_NAME': 'amneziawg-server',
            'ensure_awgctl': lambda: (events.append(('ensure_awgctl',)) or True),
            'read_meta_file': lambda p: {'listen_port': 443, 'hop_port_range': '20000-40000'},
            'meta_path': Path('/tmp/meta.json'),
            'data_lock': threading.Lock(),
            'data': {'tuic_config': {'enabled': True, 'port': 51821}},
            'awg_run': lambda args, timeout=0: (awg_args.append(args) or (0, 'ok', '')),
            'awg_err_tail': lambda *a: '',
        })

        # 1) 全角数字端口必须 400
        st1, body1 = fn(_FakeHandler('line=3&endpoint=vpn.example.com&port=５１８２０'.encode('utf-8')), '/tok/')
        self.assertEqual(st1, 400)
        self.assertFalse(body1['ok'])

        # 2) 与已启用 TUIC UDP 端口冲突必须 400
        st2, body2 = fn(_FakeHandler(b'line=3&endpoint=vpn.example.com&port=51821'), '/tok/')
        self.assertEqual(st2, 400)
        self.assertIn('TUIC', body2['error'])

        # 3) 正常安装（带前导零）须先申请重型死线再 ensure_awgctl，且 --port 去掉前导零
        st3, body3 = fn(_FakeHandler(b'line=3&endpoint=vpn.example.com&port=051822', events=events), '/tok/')
        self.assertEqual(st3, 200)
        self.assertTrue(body3['ok'])
        self.assertEqual(events[:2], [('deadline', 480, True), ('ensure_awgctl',)])
        self.assertIn('51822', awg_args[0])
        self.assertNotIn('051822', awg_args[0])

    def test_manage_awg_allows_offline_start_stop_and_extends_deadline_before_ensure_awgctl(self):
        """_h_post_manage_amneziawg 的 stop/restart 不应依赖 ensure_awgctl，且重型操作须先续期再 ensure_awgctl。"""
        events = []
        sub_calls = []

        def fake_sub(cmd, **kwargs):
            sub_calls.append(cmd)
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        fn = _extract_method('_h_post_manage_amneziawg', {
            'awg_installed': lambda: True,
            'unit_suspended': lambda u: False,
            'AWG_SVC_NAME': 'amneziawg-server',
            'ensure_awgctl': lambda force=False: (events.append(('ensure_awgctl', force)) or False),
            'awg_operation_lock': threading.Lock(),
            'subprocess': SimpleNamespace(run=fake_sub, TimeoutExpired=Exception, SubprocessError=Exception),
            'awg_run': lambda args, timeout=0: (0, 'ok', ''),
            'awg_err_tail': lambda *a: '',
            'awg_state': lambda: {'line': '3'},
        })

        # 断网导致 ensure_awgctl 返回 False 时，stop 仍须成功执行 systemctl stop
        st, body = fn(_FakeHandler(b'action=stop', events=events), '/tok/')
        self.assertEqual(st, 200, f'stop 不应被 ensure_awgctl 阻断: {body}')
        self.assertTrue(body['ok'])
        self.assertIn(['systemctl', 'stop', 'amneziawg-server'], sub_calls)
        self.assertEqual(events, [('deadline', 120, False)])

        # peer_add 遇到重型槽忙时，必须直接返回 409 且不先调用 ensure_awgctl
        events2 = []
        fn2 = _extract_method('_h_post_manage_amneziawg', {
            'VALID_AWG_NAME_RE': portal.re.compile(r'^[A-Za-z0-9_.-]{1,32}$'),
            'awg_installed': lambda: True,
            'unit_suspended': lambda u: False,
            'AWG_SVC_NAME': 'amneziawg-server',
            'ensure_awgctl': lambda force=False: (events2.append(('ensure_awgctl', force)) or True),
            'awg_operation_lock': threading.Lock(),
            'awg_run': lambda args, timeout=0: (0, 'ok', ''),
            'awg_err_tail': lambda *a: '',
            'awg_state': lambda: {'line': '3'},
        })
        st2, body2 = fn2(_FakeHandler(b'action=peer_add&name=phone&endpoint=1.2.3.4', events=events2, heavy_ok=False), '/tok/')
        self.assertEqual(st2, 409)
        self.assertEqual(events2, [('deadline', 120, True)])

    def test_sync_cert_runtime_skips_empty_truncated_cert_file(self):
        """证书文件被截断为 0 字节时，sync_cert_runtime 不得重启任何线上服务。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            empty_cert = root / 'server.crt'
            empty_cert.write_bytes(b'')
            calls = []
            with mock.patch.object(portal, '_systemd_state', return_value='active'), \
                 mock.patch.object(portal.subprocess, 'run', side_effect=lambda *a, **k: calls.append(a)):
                reloaded = portal.sync_cert_runtime(root, empty_cert)
            self.assertFalse(reloaded)
            self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
