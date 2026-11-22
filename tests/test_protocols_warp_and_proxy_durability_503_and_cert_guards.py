"""回归测试：五大协议、WARP 安装与代理管理的持久化不确定统一返回 503，及代理删权/二维码、Reality reset 与证书名防护。"""

import ast
import copy
import io
import sys
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

TREE = ast.parse((REPO / 'portal.py').read_text(encoding='utf-8'))


def _extract_method(name, extra_env):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    env['copy'] = copy
    env['AtomicWriteDurabilityError'] = portal.AtomicWriteDurabilityError
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeHandler:
    def __init__(self, body=b''):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        return True

    def reply_json(self, status, payload):
        return status, payload


class ProtocolsWarpAndProxyDurability503AndCertGuardsTests(unittest.TestCase):
    def test_five_protocol_handlers_and_install_warp_return_503_on_durability_error(self):
        """五大协议管理与 WARP 安装处理函数外层均须捕获 AtomicWriteDurabilityError 返回 503。"""
        # 1) _h_post_manage_reality (disable -> save_data 抛 AtomicWriteDurabilityError)
        class _FakeXrayPath:
            def __init__(self, p):
                self.p = str(p)
            def exists(self):
                return True
            def read_text(self, encoding='utf-8'):
                return '{"inbounds": [{"tag": "reality-in"}]}'

        fn_rel = _extract_method('_h_post_manage_reality', {
            'Path': _FakeXrayPath,
            'has_managed_inbound': lambda cfg, tag: True,
            'remove_managed_inbound': lambda cfg, tag: None,
            'apply_xray_config_transaction': lambda *a, **k: None,
            'unit_suspended': lambda u: False,
            'core_operation_lock': threading.Lock(),
            'core_operation_file_lock': nullcontext,
            'reality_apply_lock': threading.Lock(),
            'data_lock': threading.Lock(),
            'data': {'reality_config': {'enabled': True, 'port': 443}},
            'save_data': Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync failed')),
            'regenerate_page': Mock(),
        })
        st, body = fn_rel(_FakeHandler(b'action=disable'), '/tok/')
        self.assertEqual(st, 503, body)

        class _MissingPath:
            def __init__(self, p):
                self.p = str(p)
            def exists(self):
                return False

        # 2) _h_post_manage_vmess (enable -> _apply_vmess_enable 抛 AtomicWriteDurabilityError)
        h_vm = _FakeHandler(b'action=enable')
        h_vm._apply_vmess_enable = Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync'))
        fn_vm = _extract_method('_h_post_manage_vmess', {
            'Path': _MissingPath,
            'unit_suspended': lambda u: False,
            'core_operation_lock': threading.Lock(),
            'core_operation_file_lock': nullcontext,
        })
        st, body = fn_vm(h_vm, '/tok/')
        self.assertEqual(st, 503, body)

        # 3) _h_post_manage_anytls
        h_at = _FakeHandler(b'action=enable')
        h_at._apply_anytls_enable = Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync'))
        fn_at = _extract_method('_h_post_manage_anytls', {
            'unit_suspended': lambda u: False,
            'core_operation_lock': threading.Lock(),
            'core_operation_file_lock': nullcontext,
            'ANYTLS_SERVICE': 'hy2-anytls',
            '_active_anytls_config': lambda: None,
            'data_lock': threading.Lock(),
            'data': {},
        })
        st, body = fn_at(h_at, '/tok/')
        self.assertEqual(st, 503, body)

        # 4) _h_post_manage_tuic
        h_tu = _FakeHandler(b'action=enable')
        h_tu._apply_tuic_enable = Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync'))
        fn_tu = _extract_method('_h_post_manage_tuic', {
            'unit_suspended': lambda u: False,
            'core_operation_lock': threading.Lock(),
            'core_operation_file_lock': nullcontext,
            'TUIC_SERVICE': 'hy2-tuic',
            '_active_tuic_config': lambda: None,
            'data_lock': threading.Lock(),
            'data': {},
        })
        st, body = fn_tu(h_tu, '/tok/')
        self.assertEqual(st, 503, body)

        # 5) _h_post_manage_vlessenc
        h_ve = _FakeHandler(b'action=enable')
        h_ve._apply_vlessenc_enable = Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync'))
        fn_ve = _extract_method('_h_post_manage_vlessenc', {
            'Path': _MissingPath,
            'unit_suspended': lambda u: False,
            'core_operation_lock': threading.Lock(),
            'core_operation_file_lock': nullcontext,
        })
        st, body = fn_ve(h_ve, '/tok/')
        self.assertEqual(st, 503, body)

        # 6) _h_post_install_warp 源码须在外层返回 503
        src = (REPO / 'portal.py').read_text(encoding='utf-8')
        s = src.index('def _h_post_install_warp(self, prefix):')
        block = src[s:src.index('\n        def ', s + 1)]
        self.assertIn('except AtomicWriteDurabilityError', block)
        self.assertIn('self.reply_json(503,', block)

    def test_manage_proxy_delete_durability_reloads_gost_and_returns_503_and_blocks_script_qr(self):
        """代理删除遇 AtomicWriteDurabilityError 仍尝试 reload_gost 并返回 503；新增代理拦截含 <script 二维码。"""
        reload_mock = Mock(return_value=True)
        data = {'proxy_services': [{'id': 'proxy_1', 'type': 'socks5', 'port': 18080, 'username': 'u', 'password': 'p'}]}
        class _P:
            def __init__(self, p):
                self.p = str(p)
            def exists(self):
                return True
            def read_text(self, encoding='utf-8'):
                return '{}'

        fn_del = _extract_method('_manage_proxy_operation', {
            'gost_operation_lock': threading.Lock(),
            'gost_owned': lambda: True,
            'data_lock': threading.Lock(),
            'data': data,
            'proxy_services': lambda d: list(d.get('proxy_services', [])),
            'save_data': Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync')),
            'reload_gost': reload_mock,
            'Path': _P,
        })
        st, body = fn_del(_FakeHandler(), 'delete', {'id': 'proxy_1'})
        self.assertEqual(st, 503, body)
        self.assertEqual(data['proxy_services'], [])
        reload_mock.assert_called_once()

        # 新增代理：二维码带 <script 且 note 含换行控制字符
        data2 = {'proxy_services': []}
        fn_add = _extract_method('_manage_proxy_operation', {
            'gost_operation_lock': threading.Lock(),
            'gost_owned': lambda: True,
            'data_lock': threading.Lock(),
            'data': data2,
            'proxy_services': lambda d: list(d.get('proxy_services', [])),
            'save_data': Mock(),
            'reload_gost': Mock(return_value=True),
            'firewall_port': Mock(return_value=True),
            'managed_reserved_ports': lambda *a, **k: set(),
            '_listening_ports': lambda: set(),
            'meta_path': Path('/nonexistent/meta.json'),
            'read_meta_file': lambda p: {'server_name': 'node.example.com'},
            'meta_display_host': lambda m: 'node.example.com',
            'Path': _P,
            'subprocess': SimpleNamespace(
                run=lambda *a, **k: SimpleNamespace(returncode=0, stdout=b'<svg><script>x</script></svg>', stderr=b'')
            ),
        })
        st2, body2 = fn_add(_FakeHandler(), 'create', {'type': 'socks5', 'port': '18081', 'note': 'hi\r\nthere'})
        self.assertEqual(st2, 200, body2)
        self.assertEqual(body2['qr'], '')
        self.assertEqual(body2['note'], 'hithere')

    def test_vmess_certificate_tolerates_non_string_sans_and_reality_reset_catches_oserror(self):
        """_vmess_certificate 面对非字符串 SAN/CN 不得抛 TypeError；Reality reset 读盘 OSError 返回 409 而非 500。"""
        class _FakePath:
            def __init__(self, p):
                self.p = str(p)
            def is_file(self):
                return True

        def _fake_run(cmd, **kw):
            if '-checkend' in cmd:
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout='notBefore=Jan  1 00:00:00 2020 GMT\n', stderr='')

        fn_cert = _extract_method('_vmess_certificate', {
            'Path': _FakePath,
            '_resolve_live_cert': lambda d: ('/etc/hysteria/cert.pem', 123, [None, 'other.example.com', 456], False),
            'subprocess': SimpleNamespace(run=_fake_run),
            'certificate_covers_domain': lambda d, s, c: False,
        })
        with self.assertRaises(RuntimeError) as ctx:
            fn_cert(_FakeHandler(), 'target.example.com', 'VMess')
        self.assertIn('other.example.com', str(ctx.exception))

        class _ErrXrayPath:
            def __init__(self, p):
                self.p = str(p)
            def exists(self):
                return True
            def read_text(self, encoding='utf-8'):
                raise PermissionError('denied')

        fn_rel = _extract_method('_h_post_manage_reality', {
            'Path': _ErrXrayPath,
        })
        st, body = fn_rel(_FakeHandler(b'action=reset'), '/tok/')
        self.assertEqual(st, 409, body)


if __name__ == '__main__':
    unittest.main()
