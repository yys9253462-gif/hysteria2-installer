"""回归测试：门户所有对外主机与自签标记读取均应经 clean_node_identity / meta_display_host 清洗。"""
import ast
import importlib.util
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_meta_host_test', ROOT / 'portal.py')
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


class MetaDisplayHostConsistencyTests(unittest.TestCase):
    def test_ensure_portal_access_handles_string_false_and_missing_public_ip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = {'token': 'tok123', 'api_key': 'ak123'}
            meta = {'is_insecure': 'false', 'server_name': 'vpn.example.com', 'public_ip': '203.0.113.5', 'subscription_port': 8443}
            access, rebuilt = portal.ensure_portal_access(root, meta, data)
            self.assertTrue(rebuilt)
            self.assertIn('https://vpn.example.com:8443/tok123/', access['url'])

            # 自签模式但缺少 public_ip 时也不应 KeyError 崩溃
            root2 = Path(td) / 'r2'
            root2.mkdir()
            access2, _ = portal.ensure_portal_access(root2, {'is_insecure': True, 'server_name': 'fallback.example.com', 'subscription_port': 8443}, dict(data))
            self.assertIn('https://fallback.example.com:8443/tok123/', access2['url'])

    def test_cert_status_treats_string_false_as_trusted_and_renewable(self):
        with tempfile.TemporaryDirectory() as td:
            meta = {'cert_type': 'acme', 'is_insecure': 'false', 'server_name': 'vpn.example.com'}
            info = portal.cert_status(Path(td), meta=meta)
            self.assertFalse(info['is_insecure'])
            self.assertTrue(info['renewal_managed'])

    def test_proxy_services_endpoint_uses_domain_when_is_insecure_is_string_false(self):
        replies = []
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            reply_json=lambda code, payload: replies.append((code, payload)),
        )
        ns = dict(
            portal.__dict__,
            data={'proxy_services': []},
            data_lock=threading.RLock(),
            meta_path=Path('unused'),
            read_meta_file=lambda _: {'is_insecure': 'false', 'server_name': 'vpn.example.com', 'public_ip': '203.0.113.9'},
            gost_status=lambda: True,
        )
        fn = _extract_method('_h_get_proxy_services', ns)
        fn(handler, 'proxy-services')
        self.assertEqual(replies[-1][0], 200)
        self.assertEqual(replies[-1][1]['host'], 'vpn.example.com')

    def test_api_proxy_list_and_capabilities_normalize_string_false(self):
        meta = {'is_insecure': 'false', 'server_name': 'vpn.example.com', 'public_ip': '203.0.113.9'}
        replies = []
        handler = SimpleNamespace(
            path='/api/v1/proxy-services/list',
            headers={},
            check_rate_limit=lambda **kw: True,
            verify_api_key=lambda: True,
            reply_json=lambda code, payload: replies.append((code, payload)),
            reply=lambda code, body, *a: replies.append((code, body)),
        )
        ns = dict(
            portal.__dict__,
            data={'token': 'tok', 'users': {}, 'proxy_services': []},
            data_lock=threading.RLock(),
            meta_path=Path('unused'),
            portal_path=Path('unused'),
            read_meta_file=lambda _: meta,
            gost_status=lambda: False,
        )
        do_get = _extract_method('do_GET', ns)
        do_get(handler)
        self.assertEqual(replies[-1][0], 200)
        self.assertEqual(replies[-1][1]['host'], 'vpn.example.com')

        handler.path = '/api/v1/capabilities'
        ns['_cert_summary'] = lambda *a: {}
        ns['_core_version'] = lambda: ''
        ns['_systemd_state'] = lambda *a: 'inactive'
        ns['awg_installed'] = lambda: False
        ns['AWG_SVC_NAME'] = 'awg-quick@awg0'
        ns['_active_reality_config'] = lambda: None
        ns['_active_vmess_config'] = lambda: None
        ns['_active_vlessenc_config'] = lambda: None
        ns['_active_anytls_config'] = lambda: None
        ns['_active_tuic_config'] = lambda: None
        ns['subprocess'] = SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(returncode=1, stdout=''))
        do_get(handler)
        self.assertEqual(replies[-1][0], 200)
        self.assertIs(replies[-1][1]['node']['is_insecure'], False)


if __name__ == '__main__':
    unittest.main()
