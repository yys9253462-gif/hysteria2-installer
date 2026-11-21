import ast
import io
import os
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SRC = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _extract_method(name, ns):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(SRC, node)
            exec('class _H:\n' + '\n'.join('    ' + ln for ln in src.splitlines()), ns)
            return getattr(ns['_H'], name)
    raise AssertionError(f'missing method {name}')


class TestCoreBinaryBoundedAndProxyGuards(unittest.TestCase):
    def test_copy_stream_bounded_rejects_oversized_stream(self):
        """_copy_stream_bounded 必须在流超过字节上限时立刻拒绝。"""
        self.assertTrue(hasattr(portal, '_copy_stream_bounded'))
        src = io.BytesIO(b'x' * 2048)
        dst = io.BytesIO()
        with self.assertRaises(ValueError):
            portal._copy_stream_bounded(src, dst, 1024, chunk_size=256)

    def test_install_xray_binary_rejects_symlink_zip_entry_and_oversized_download(self):
        """install_xray_binary 必须拒绝 zip 内符号链接成员与超限下载流。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zi = zipfile.ZipInfo('xray')
            zi.create_system = 3  # Unix
            zi.external_attr = (0o120777 << 16)
            zf.writestr(zi, '/etc/passwd')
        payload = buf.getvalue()
        import hashlib
        digest = hashlib.sha256(payload).hexdigest()

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        with mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(portal, '_xray_version', return_value=''), \
             mock.patch.object(portal, 'fetch_expected_sha256', return_value=digest), \
             mock.patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: _Resp(payload)):
            ok, msg = portal.install_xray_binary()
        self.assertFalse(ok)
        self.assertIn('链接', msg)

        # 超限下载流直接截断拒绝
        big_payload = b'A' * 1024
        with mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(portal, '_xray_version', return_value=''), \
             mock.patch.object(portal, 'fetch_expected_sha256', return_value='0' * 64), \
             mock.patch.object(portal, '_MAX_BINARY_ARCHIVE_BYTES', 256), \
             mock.patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: _Resp(big_payload)):
            ok2, msg2 = portal.install_xray_binary()
        self.assertFalse(ok2)
        self.assertIn('超过上限', msg2)

    def test_install_gost_rejects_unsupported_arch_and_uses_bounded_stream(self):
        """_h_post_install_gost 必须拒绝未知架构且下载/解压均使用受限流复制。"""
        start = SRC.index('        def _h_post_install_gost(self, prefix):')
        end = SRC.index('        def _h_post_install_amneziawg(self, prefix):', start)
        body = SRC[start:end]
        self.assertNotIn("arch = 'linux_amd64'\n", body.split("elif 'armv7'")[1].split('# 动态探测')[0])
        self.assertIn('_copy_stream_bounded(', body)
        self.assertIn('UnicodeDecodeError', body)

    def test_manage_proxy_rejects_fullwidth_port_non_str_creds_and_rolls_back_on_reload_exception(self):
        """_manage_proxy_operation 须拦截全角端口与非字符串账号密码，且 reload_gost 抛异常也必须回滚。"""
        data = {'proxy_services': []}
        saved_snapshots = []
        reloads = []

        def fake_save():
            saved_snapshots.append(list(data['proxy_services']))

        def fake_reload():
            reloads.append(list(data['proxy_services']))
            if len(reloads) == 1:
                raise RuntimeError('systemctl timeout')
            return True

        ns = {
            'gost_operation_lock': threading.Lock(),
            'Path': lambda p: mock.MagicMock(
                exists=lambda: True,
                read_text=mock.MagicMock(side_effect=OSError('missing')),
            ),
            'gost_owned': lambda: True,
            'data_lock': threading.Lock(),
            'copy': __import__('copy'),
            'data': data,
            'proxy_services': portal.proxy_services,
            're': __import__('re'),
            'read_meta_file': lambda p: {'public_ip': '1.2.3.4'},
            'meta_path': Path('/tmp/meta.json'),
            'json': __import__('json'),
            'managed_reserved_ports': lambda *a, **k: set(),
            '_listening_ports': lambda: set(),
            'random': __import__('random'),
            'secrets': __import__('secrets'),
            'time': __import__('time'),
            'save_data': fake_save,
            'AtomicWriteDurabilityError': portal.AtomicWriteDurabilityError,
            'reload_gost': fake_reload,
            '_log_ignored': lambda *a, **k: None,
            'firewall_port': lambda *a, **k: True,
            'meta_display_host': lambda m: '1.2.3.4',
            'quote': portal.quote,
            'subprocess': __import__('subprocess'),
            'gost_tls_paths': lambda p: ('c', 'k'),
            'portal_path': Path('/tmp/portal.json'),
            'protocol_port_in_use': lambda *a, **k: False,
        }
        fn = _extract_method('_manage_proxy_operation', ns)
        dummy = object()

        # 全角端口必须 400
        st1, body1 = fn(dummy, 'create', {'type': 'socks5', 'port': '８０８０'})
        self.assertEqual(st1, 400)
        self.assertFalse(body1['ok'])

        # 布尔端口必须 400
        st2, body2 = fn(dummy, 'create', {'type': 'socks5', 'port': True})
        self.assertEqual(st2, 400)

        # 非字符串用户名必须 400
        st3, body3 = fn(dummy, 'create', {'type': 'socks5', 'port': '18080', 'username': ['bad']})
        self.assertEqual(st3, 400)

        # reload_gost 抛异常时必须完整回滚 data['proxy_services']
        st4, body4 = fn(dummy, 'create', {'type': 'socks5', 'port': '18080', 'username': 'u1', 'password': 'p1'})
        self.assertEqual(st4, 500)
        self.assertFalse(body4['ok'])
        self.assertEqual(data['proxy_services'], [])
        self.assertEqual(len(reloads), 2)


if __name__ == '__main__':
    unittest.main()
