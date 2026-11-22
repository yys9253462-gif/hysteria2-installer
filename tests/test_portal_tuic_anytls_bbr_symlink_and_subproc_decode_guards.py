"""回归测试：TUIC/AnyTLS 符号链接与超大配置防护、BBR 文件防劫持及剩余子进程 UTF-8 替换解码。"""

import ast
import copy
import io
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _extract_func(name, extra_env):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    env.update(extra_env)
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])),
            f'<{name}>',
            'exec',
        ),
        env,
    )
    return env[name]


class _DummyHandler:
    def __init__(self, body=b''):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.deadlines = []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.deadlines.append((seconds, heavy))
        return True

    def _vmess_certificate(self, domain, label):
        return '/c.crt', '/c.key', domain

    def reply_json(self, status, payload):
        return status, payload


class PortalTuicAnytlsBbrSymlinkAndSubprocDecodeGuardsTests(unittest.TestCase):
    def test_apply_tuic_enable_rejects_symlink_unit_and_oversized_config(self):
        """_apply_tuic_enable 须拒绝符号链接服务单元与超大 tuic.json，避免解引用与 OOM。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            portal_file = root / 'portal.json'
            portal_file.write_text('{}', encoding='utf-8')
            meta_file = root / 'client_meta.json'
            meta_file.write_text('{"server_name": "ex.com", "listen_port": 443}', encoding='utf-8')
            fake_unit = root / 'tuic.service'
            fake_unit.write_text('unit', encoding='utf-8')
            cfg_path = root / portal.TUIC_CONFIG_NAME

            unit_is_sym = True
            unit_size = 16
            applied = []

            class _FakeUnitPath:
                def __init__(self, p):
                    self._p = fake_unit if str(p).endswith('.service') else Path(p)

                def is_symlink(self):
                    return self._p == fake_unit and unit_is_sym

                def exists(self):
                    return self._p.exists()

                def lstat(self):
                    return SimpleNamespace(st_size=unit_size)

                def stat(self):
                    return self._p.stat()

                def read_bytes(self):
                    if self._p == fake_unit and unit_is_sym:
                        raise AssertionError('不应读取被拒的符号链接服务单元')
                    return self._p.read_bytes()

            def _make_env():
                return {
                    'Path': _FakeUnitPath,
                    'portal_path': portal_file,
                    'meta_path': meta_file,
                    'tuic_apply_lock': threading.Lock(),
                    'data_lock': threading.Lock(),
                    'data': {'tuic_config': {'port': 4433, 'domain': 'ex.com', 'sni': 'ex.com', 'secret': 's'}},
                    '_singbox_version': lambda: (1, 12, 0),
                    'pick_tuic_port': lambda *a, **k: 4433,
                    '_systemd_state': lambda svc: 'inactive',
                    'tuic_users': lambda d: [],
                    'build_tuic_config': lambda *a, **k: {},
                    'apply_anytls_config': lambda *a, **k: applied.append(True),
                    '_systemd_service_snapshot': lambda svc: {},
                    '_restore_systemd_unit_file': lambda *a, **k: None,
                    'save_data': lambda: None,
                    'subprocess': SimpleNamespace(run=lambda *a, **k: SimpleNamespace(returncode=0)),
                }

            fn = _extract_func('_apply_tuic_enable', _make_env())
            with self.assertRaisesRegex(RuntimeError, '符号链接'):
                fn(_DummyHandler())
            self.assertEqual(applied, [])

            # 场景 2：unit 正常但 tuic.json 体积超过 4 MiB
            unit_is_sym = False
            cfg_path.write_bytes(b'x' * (4 * 1024 * 1024 + 16))
            fn2 = _extract_func('_apply_tuic_enable', _make_env())
            with self.assertRaisesRegex(RuntimeError, '4 MiB'):
                fn2(_DummyHandler())
            self.assertEqual(applied, [])

    def test_manage_anytls_and_tuic_disable_reject_symlink_and_oversized_config(self):
        """禁用 AnyTLS / TUIC 时，若配置文件为符号链接或超 4 MiB，须返回 500 且不执行停服。"""
        for proto_name, method_name, cfg_name, cfg_key, lock_name, active_fn_name in (
            ('AnyTLS', '_h_post_manage_anytls', portal.ANYTLS_CONFIG_NAME, 'anytls_config', 'anytls_apply_lock', '_active_anytls_config'),
            ('TUIC', '_h_post_manage_tuic', portal.TUIC_CONFIG_NAME, 'tuic_config', 'tuic_apply_lock', '_active_tuic_config'),
        ):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                portal_file = root / 'portal.json'
                portal_file.write_text('{}', encoding='utf-8')
                cfg_path = root / cfg_name
                cfg_path.write_bytes(b'z' * (4 * 1024 * 1024 + 8))
                calls = []
                env = {
                    'portal_path': portal_file,
                    'core_operation_lock': threading.Lock(),
                    'core_operation_file_lock': lambda: nullcontext(),
                    lock_name: threading.Lock(),
                    'data_lock': threading.Lock(),
                    'data': {cfg_key: {'enabled': True, 'port': 4444}},
                    active_fn_name: lambda: {'enabled': True, 'port': 4444},
                    'subprocess': SimpleNamespace(run=lambda *a, **k: calls.append(a)),
                    '_systemd_service_snapshot': lambda svc: {},
                    '_systemd_state': lambda svc: 'active',
                    '_service_stop_confirmed': lambda *a, **k: True,
                    '_restore_systemd_service_state': lambda *a, **k: True,
                    'save_data': lambda: None,
                    'close_protocol_port': lambda *a, **k: None,
                }
                fn = _extract_func(method_name, env)
                st, body = fn(_DummyHandler(b'action=disable'), f'manage-{proto_name.lower()}')
                self.assertEqual(st, 500, f'{proto_name} 超大配置应返回 500，实际: {st} {body}')
                self.assertFalse(body['ok'])
                self.assertIn('4 MiB', body['error'])
                self.assertEqual(calls, [], f'{proto_name} 被拒前不应调用 systemctl')

                # 场景 2：配置文件表现为符号链接
                cfg_path.write_bytes(b'{}')
                with patch.object(Path, 'is_symlink', autospec=True,
                                  side_effect=lambda self_p: self_p == cfg_path):
                    st2, body2 = fn(_DummyHandler(b'action=disable'), f'manage-{proto_name.lower()}')
                self.assertEqual(st2, 500, f'{proto_name} 符号链接配置应返回 500，实际: {st2} {body2}')
                self.assertFalse(body2['ok'])
                self.assertIn('符号链接', body2['error'])
                self.assertEqual(calls, [])

    def test_set_bbr_locked_rejects_symlink_and_oversized_files(self):
        """_set_bbr_locked 须拒绝符号链接与超 1 MiB 原配置，且不执行 sysctl -p。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mod_file = root / 'bbr.conf'
            sys_file = root / '99-bbr.conf'
            sys_file.write_bytes(b'a' * (1024 * 1024 + 32))
            sysctl_calls = []

            def _fake_path(p):
                sp = str(p)
                if sp.endswith('bbr.conf') and 'modules-load' in sp:
                    return mod_file
                if sp.endswith('99-bbr.conf'):
                    return sys_file
                return Path(p)

            def _fake_run(cmd, **kwargs):
                sysctl_calls.append((cmd, kwargs))
                if cmd[:2] == ['sysctl', '-n'] and cmd[2] == 'net.ipv4.tcp_available_congestion_control':
                    return SimpleNamespace(returncode=0, stdout='cubic bbr\n', stderr='')
                if cmd[:2] == ['sysctl', '-n']:
                    return SimpleNamespace(returncode=0, stdout='cubic\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            fn = _extract_func('_set_bbr_locked', {
                'Path': _fake_path,
                'subprocess': SimpleNamespace(run=_fake_run, SubprocessError=subprocess.SubprocessError),
                'data_lock': threading.Lock(),
                'data': {},
                'save_data': lambda: None,
            })

            st, body = fn(_DummyHandler(b'version=v1'))
            self.assertEqual(st, 500, f'超大原配置应返回 500，实际: {st} {body}')
            self.assertFalse(body['ok'])
            self.assertIn('1 MiB', body['error'])
            self.assertFalse(any(cmd[:2] == ['sysctl', '-p'] for cmd, _ in sysctl_calls))

            # 场景 2：符号链接目标直接拒绝
            sys_file.write_text('net.core.default_qdisc = fq\n', encoding='utf-8')
            with patch.object(Path, 'is_symlink', autospec=True,
                              side_effect=lambda self_p: self_p == sys_file):
                st2, body2 = fn(_DummyHandler(b'version=v1'))
            self.assertEqual(st2, 500, f'符号链接目标应返回 500，实际: {st2} {body2}')
            self.assertFalse(body2['ok'])
            self.assertIn('符号链接', body2['error'])

    def test_remaining_portal_subprocess_text_calls_use_errors_replace(self):
        """门户中全部关键 subprocess.run(..., text=True) 须显式指定 errors='replace'。"""
        targets = {
            '_hy2_runtime_identity',
            'generate_vless_encryption_pair',
            '_nft_input_chain',
            '_generate_and_apply_reality',
            '_h_post_manage_amneziawg',
            '_h_post_install_xray',
            '_h_post_install_core',
            '_h_get_cores_status',
            '_h_post_install_warp',
            '_h_get_check_version',
            '_set_bbr_locked',
        }
        missing = []
        found_funcs = set()
        for node in ast.walk(TREE):
            if not isinstance(node, ast.FunctionDef) or node.name not in targets:
                continue
            found_funcs.add(node.name)
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                if isinstance(call.func, ast.Attribute) and call.func.attr == 'run':
                    kw = {k.arg: k.value for k in call.keywords if k.arg}
                    text_kw = kw.get('text')
                    if isinstance(text_kw, ast.Constant) and text_kw.value is True:
                        err_kw = kw.get('errors')
                        if not (isinstance(err_kw, ast.Constant) and err_kw.value == 'replace'):
                            missing.append((node.name, call.lineno))
        self.assertEqual(found_funcs, targets)
        self.assertEqual(missing, [], f'以下子进程调用缺少 errors="replace": {missing}')


if __name__ == '__main__':
    unittest.main()
