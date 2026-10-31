import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


class TestRealityClientSyncGuards(unittest.TestCase):
    """_sync_reality_clients 的降级守卫。

    真实场景：不是每台机器都装了 Reality。
    开户/销户时若无脑去写 /etc/hysteria/xray.json，会在
    「没装 xray 的节点」上凭空创建配置、或抛权限错误把 HTTP handler 打死。
    """

    def test_missing_config_is_noop_when_xray_is_stopped(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d, \
             patch.object(portal, '_systemd_state', return_value='inactive'):
            root = Path(d)
            self.assertTrue(portal.enforce_node_access(root, {'users': {}}))
            self.assertFalse((root / 'xray.json').exists())

    def test_missing_config_while_xray_active_cannot_confirm_revocation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d, \
             patch.object(portal, '_systemd_state', return_value='active'):
            root = Path(d)
            (root / 'usage-meter-config.json').write_text(json.dumps(
                {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 'fixture'}}),
                encoding='utf-8')
            with patch.object(portal.urllib.request, 'urlopen', return_value=type(
                    'Response', (), {'__enter__': lambda self: self,
                                     '__exit__': lambda *args: None,
                                     'read': lambda self: b'{}'})()):
                with self.assertRaisesRegex(RuntimeError, 'xray.json missing while Xray is active'):
                    portal.enforce_node_access(root, {'users': {'revoked': {'status': 'disabled'}}},
                                               ['revoked'])
            self.assertFalse((root / 'xray.json').exists())

    def test_revocation_transaction_uses_protocol_apply_lock(self):
        from unittest.mock import patch
        import contextlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / 'xray.json'
            cfg = {'inbounds': [
                {'tag': portal.REALITY_INBOUND_TAG, 'settings': {'clients': []}},
                {'tag': portal.VMESS_INBOUND_TAG, 'settings': {'clients': []}},
            ]}
            path.write_text(json.dumps(cfg), encoding='utf-8')
            (root / 'usage-meter-config.json').write_text(json.dumps(
                {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 'fixture'}}),
                encoding='utf-8')
            lock_state = []
            protocol_lock = contextlib.nullcontext()
            with patch.object(portal, '_systemd_state', return_value='inactive'), \
                 patch.object(portal.subprocess, 'run') as run, \
                 patch.object(portal, '_apply_xray_access_snapshot',
                              side_effect=lambda *args: (lock_state.append(args[-1]) or True)), \
                 patch.object(portal.urllib.request, 'urlopen', return_value=type(
                    'Response', (), {'__enter__': lambda self: self,
                                     '__exit__': lambda *args: None,
                                     'read': lambda self: b'{}'})()):
                self.assertTrue(portal.enforce_node_access(
                    root, {'users': {'gone': {'status': 'disabled'}}}, ['gone'], protocol_lock))
            self.assertEqual(len(lock_state), 1)
            self.assertIs(lock_state[0], protocol_lock)

    def test_anytls_failure_does_not_skip_xray_revocation(self):
        from unittest.mock import patch
        calls = []
        with patch.object(portal, 'sync_anytls_users', side_effect=ValueError('broken')), \
             patch.object(portal, '_enforce_node_access_xray_hy2', side_effect=lambda *a: calls.append(a) or True):
            with self.assertRaises(RuntimeError):
                portal.enforce_node_access('/tmp/unused', {'users': {}})
        self.assertEqual(len(calls), 1)

    def test_corrupt_xray_shape_cannot_confirm_revocation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / 'xray.json'
            for content in ('[]', '"broken"', '{"inbounds": 7}', '{"inbounds": [null]}',
                            '{"inbounds": [{"tag":"vmess-ws-in"},{"tag":"vmess-ws-in"}]}'):
                with self.subTest(content=content):
                    path.write_text(content, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        portal.enforce_node_access(root, {'users': {}})
                    self.assertEqual(path.read_text(encoding='utf-8'), content)

    def test_source_handles_unreadable_json(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'xray.json').write_text('invalid',encoding='utf-8')
            with self.assertRaises(json.JSONDecodeError):
                portal.enforce_node_access(root,{'users':{}})
            self.assertEqual((root/'xray.json').read_text(encoding='utf-8'),'invalid')


class TestEncodingHardening(unittest.TestCase):
    """所有 write_text 必须显式 encoding='utf-8'。

    实测（2026-10-03 Windows）：Path.write_text 不给 encoding 时跟随
    locale，Windows 是 GBK —— 页面里含 `₂` 之类字符时直接
    UnicodeEncodeError，把 HTTP handler 打死，客户端只看到
    "Remote end closed connection without response"，完全看不出是编码问题。
    Linux 上是 UTF-8 所以不会踩 —— 也就是说这个 bug 在开发机（Linux）
    上永远发现不了。
    """

    def test_no_write_text_without_encoding(self):
        src = (Path(__file__).resolve().parents[1] / 'portal.py').read_text(encoding='utf-8')
        import ast
        tree = ast.parse(src)
        bad = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr == 'write_text'):
                continue
            kw = {k.arg for k in node.keywords}
            if 'encoding' not in kw:
                bad.append(node.lineno)
        self.assertEqual(bad, [],
                         '这些 write_text 没带 encoding：行 %s。'
                         'Windows 上会因 GBK 打死 HTTP handler' % bad)

    def test_save_data_uses_utf8(self):
        import inspect
        src = inspect.getsource(portal.serve)
        i = src.find('    def save_data():')
        self.assertGreaterEqual(i, 0, 'serve() must define save_data')
        end = src.find('\n    def ', i + 1)
        body = src[i:end if end >= 0 else len(src)]
        self.assertIn("encoding='utf-8'", body,
                      'save_data 必须显式 UTF-8 —— 它写的是整个 portal.json')


if __name__ == '__main__':
    unittest.main(verbosity=2)
