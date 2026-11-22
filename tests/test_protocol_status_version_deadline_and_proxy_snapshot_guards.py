"""回归测试：五大协议状态接口二维码/端口/脏字段清洗、check-version 死线续期与 proxy-services 快照隔离。"""

import ast
import copy
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
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
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeHandler:
    def __init__(self, path='/tok/check-version'):
        self.path = path
        self.deadlines = []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.deadlines.append((seconds, heavy))
        return True

    def reply_json(self, status, payload):
        return status, payload


class _FakeSubproc:
    def __init__(self, svg_bytes):
        self.svg_bytes = svg_bytes

    def run(self, *args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=self.svg_bytes, stderr=b'')


class _AlwaysExistsPath:
    def __init__(self, p):
        self.p = str(p)

    def exists(self):
        return True

    def read_text(self, encoding='utf-8'):
        return '{}'


class ProtocolStatusVersionDeadlineAndProxySnapshotGuardsTests(unittest.TestCase):
    def test_protocol_status_handlers_strip_script_svg_bad_ports_and_dirty_fields(self):
        """五大协议状态接口均须拦截含 <script 的 SVG、清洗非有限/布尔端口与非字符串/含控制字符字段。"""
        evil_svg = b'<svg><script>alert(1)</script></svg>'

        # 1) vmess-status
        fn_vmess = _extract_method('_h_get_vmess_status', {
            'Path': _AlwaysExistsPath,
            'managed_inbound_active': lambda cfg, tag: True,
            'data_lock': threading.Lock(),
            'data': {
                'vmess_config': {
                    'uri': 'vmess://abc',
                    'uuid': 12345,
                    'domain': 'bad\ndomain',
                    'sni': ['list'],
                    'ws_path': '/ws\r\n',
                    'port': float('inf'),
                }
            },
            'subprocess': _FakeSubproc(evil_svg),
        })
        st, body = fn_vmess(_FakeHandler(), 'vmess-status')
        self.assertEqual(st, 200)
        cfg = body['config']
        self.assertEqual(cfg['qr_svg'], '')
        self.assertEqual(cfg['port'], 0)
        self.assertEqual(cfg['uuid'], '')
        self.assertEqual(cfg['domain'], '')
        self.assertEqual(cfg['sni'], '')
        self.assertEqual(cfg['ws_path'], '')
        json.dumps(body, allow_nan=False)

        # 2) vlessenc-status
        fn_vless = _extract_method('_h_get_vlessenc_status', {
            'Path': _AlwaysExistsPath,
            'managed_inbound_active': lambda cfg, tag: True,
            'reality_uuid_for_user': lambda uid: 'u-1',
            'data_lock': threading.Lock(),
            'data': {
                'vlessenc_config': {
                    'uri': 'vless://abc',
                    'domain': 'evil\r\n.com',
                    'sni': 999,
                    'port': True,
                }
            },
            'subprocess': _FakeSubproc(evil_svg),
        })
        st, body = fn_vless(_FakeHandler(), 'vlessenc-status')
        self.assertEqual(st, 200)
        cfg = body['config']
        self.assertEqual(cfg['qr_svg'], '')
        self.assertEqual(cfg['port'], 0)
        self.assertEqual(cfg['domain'], '')
        self.assertEqual(cfg['sni'], '')
        json.dumps(body, allow_nan=False)

        # 3) anytls-status（含 anytls_uri_for_user 抛异常容错）
        fn_anytls = _extract_method('_h_get_anytls_status', {
            '_active_anytls_config': lambda: {'domain': 'a\nb', 'sni': None, 'port': float('nan')},
            '_systemd_state': lambda svc: 'active',
            '_singbox_version': lambda: (1, 12, 0),
            'anytls_uri_for_user': lambda *a, **k: (_ for _ in ()).throw(ValueError('corrupt cfg')),
            'subprocess': _FakeSubproc(evil_svg),
        })
        st, body = fn_anytls(_FakeHandler(), 'anytls-status')
        self.assertEqual(st, 200)
        self.assertEqual(body['config']['uri'], '')
        self.assertEqual(body['config']['port'], 0)
        self.assertEqual(body['config']['domain'], '')
        self.assertEqual(body['config']['sni'], '')
        json.dumps(body, allow_nan=False)

        # 4) tuic-status（含 tuic_uri_for_user 返回有效 URI 但二维码带 <script）
        fn_tuic = _extract_method('_h_get_tuic_status', {
            '_active_tuic_config': lambda: {'domain': 'ok.example.com', 'sni': 'ok\x00sni', 'port': '99999'},
            '_systemd_state': lambda svc: 'active',
            '_singbox_version': lambda: (1, 12, 0),
            'tuic_uri_for_user': lambda *a, **k: 'tuic://abc',
            'subprocess': _FakeSubproc(evil_svg),
        })
        st, body = fn_tuic(_FakeHandler(), 'tuic-status')
        self.assertEqual(st, 200)
        self.assertEqual(body['config']['qr_svg'], '')
        self.assertEqual(body['config']['port'], 0)
        self.assertEqual(body['config']['domain'], 'ok.example.com')
        self.assertEqual(body['config']['sni'], '')

        # 5) reality-status
        fn_reality = _extract_method('_h_get_reality_status', {
            'Path': _AlwaysExistsPath,
            'managed_inbound_active': lambda cfg, tag: True,
            'data_lock': threading.Lock(),
            'data': {
                'reality_config': {
                    'uri': 'vless://rel',
                    'uuid': 'id\r\n',
                    'public_key': 123,
                    'short_id': ['bad'],
                    'dest_sni': 'bad\nsni',
                    'port': float('inf'),
                }
            },
            'subprocess': _FakeSubproc(evil_svg),
        })
        st, body = fn_reality(_FakeHandler(), 'reality-status')
        self.assertEqual(st, 200)
        cfg = body['config']
        self.assertEqual(cfg['qr_svg'], '')
        self.assertEqual(cfg['port'], 443)
        self.assertEqual(cfg['uuid'], '')
        self.assertEqual(cfg['pub_key'], '')
        self.assertEqual(cfg['short_id'], '')
        self.assertEqual(cfg['sni'], 'www.apple.com')
        json.dumps(body, allow_nan=False)

    def test_check_version_extends_deadline(self):
        """_h_get_check_version 联网前须续期连接死线（>=45 秒）。"""
        fn = _extract_method('_h_get_check_version', {
            '_ver_cache_lock': threading.Lock(),
            '_ver_cache': {'t': 1e12, 'shas': {}},
            '_core_ver_cache': {'t': 1e12, 'tag': '2.6.0'},
            'subprocess': SimpleNamespace(run=lambda *a, **k: SimpleNamespace(stdout='Version: v2.6.0\n')),
            'PORTAL_SELF': Path('/tmp/portal.py'),
            '_local_blob_sha': lambda p: 'a' * 40,
            '_remote_root_shas': lambda: {},
            'portal_bundle_version': lambda lb, rs: {
                'current': 'aaaaaaa', 'latest': '', 'has_update': False,
                'status': 'unknown', 'changed_files': [], 'unknown_files': [],
            },
            '_version_triple': lambda p, n: ('', '', False),
            '_usage_runtime': None,
            'usage_meter': None,
            'usage_summary': lambda uid: {},
            'AWG_CTL': '/nonexistent/awgctl',
        })
        h = _FakeHandler('/tok/check-version')
        st, body = fn(h, 'check-version')
        self.assertEqual(st, 200)
        self.assertTrue(any(sec >= 45 for sec, _ in h.deadlines), f'未续期 >=45s 死线: {h.deadlines}')

    def test_proxy_services_returns_detached_dict_snapshot(self):
        """_h_get_proxy_services 须在锁内浅拷贝字典条目并过滤非字典脏项，防锁外并发篡改。"""
        orig = {'id': 'p1', 'type': 'socks5', 'port': 1080}
        data = {'proxy_services': [orig, None, 'broken']}
        fn = _extract_method('_h_get_proxy_services', {
            'data_lock': threading.Lock(),
            'data': data,
            'proxy_services': lambda d: list(d.get('proxy_services', [])),
            'meta_path': Path('/nonexistent/meta.json'),
            'read_meta_file': lambda p: {'server_name': 'node.example.com'},
            'meta_display_host': lambda m: 'node.example.com',
            'gost_status': lambda: True,
        })
        st, body = fn(_FakeHandler('/tok/proxy-services'), 'proxy-services')
        self.assertEqual(st, 200)
        self.assertEqual(len(body['services']), 1)
        self.assertIsNot(body['services'][0], orig)


if __name__ == '__main__':
    unittest.main()
