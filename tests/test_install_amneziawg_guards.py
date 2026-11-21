"""回归测试：_h_post_install_amneziawg 遵守流量超额停用限制，并拦截与自定义端口跳跃区间或主端口冲突的端口。"""

import ast
import copy
import io
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_install_awg(extra_env):
    tree = ast.parse(PORTAL.read_text(encoding='utf-8'))
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == '_h_post_install_amneziawg'
    )
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    env['awg_endpoint_error'] = lambda ep: ''
    env.update(extra_env)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), '<iawg>', 'exec'), env)
    return env['_h_post_install_amneziawg']


class _FakeHandler:
    def __init__(self, body):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        return True

    def reply_json(self, status, payload):
        return status, payload


class InstallAmneziawgGuardsTests(unittest.TestCase):
    def test_refuses_install_while_traffic_suspended(self):
        called = []
        fn = _extract_install_awg({
            'unit_suspended': lambda u: True,
            'AWG_SVC_NAME': 'amneziawg-server',
            'ensure_awgctl': lambda: (called.append('ctl') or True),
            'read_meta_file': lambda p: {},
            'meta_path': Path('/tmp/client_meta.json'),
        })
        status, payload = fn(_FakeHandler(b'line=3&endpoint=vpn.example.com&port=51820'), '/tok/')
        self.assertEqual(status, 409)
        self.assertFalse(payload['ok'])
        self.assertEqual(called, [], '超额停用期间不应拉起 AWG 安装')

    def test_rejects_port_inside_custom_hopping_range_or_hy2_listen_port(self):
        fn = _extract_install_awg({
            'unit_suspended': lambda u: False,
            'AWG_SVC_NAME': 'amneziawg-server',
            'ensure_awgctl': lambda: True,
            'read_meta_file': lambda p: {'listen_port': 5443, 'hop_port_range': '45000-48000'},
            'meta_path': Path('/tmp/client_meta.json'),
        })
        status1, payload1 = fn(_FakeHandler(b'line=3&endpoint=vpn.example.com&port=46000'), '/tok/')
        self.assertEqual(status1, 400)
        self.assertIn('45000', payload1['error'])

        status2, payload2 = fn(_FakeHandler(b'line=3&endpoint=vpn.example.com&port=5443'), '/tok/')
        self.assertEqual(status2, 400)
        self.assertIn('5443', payload2['error'])


if __name__ == '__main__':
    unittest.main()
