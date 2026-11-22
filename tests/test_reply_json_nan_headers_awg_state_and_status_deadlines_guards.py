"""回归测试：reply_json 严禁输出 NaN/Infinity、reply 防 CRLF 响应头注入、awg_state 脏数据清洗与 warp/cert 死线续期。"""

import ast
import copy
import io
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

TREE = ast.parse((REPO / 'portal.py').read_text(encoding='utf-8'))


def _extract_fn(name, extra_env):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    env = dict(portal.__dict__)
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeNetHandler:
    def __init__(self):
        self.status = None
        self.headers_sent = []
        self.wfile = io.BytesIO()
        self.connection = SimpleNamespace(shutdown=lambda *a: None)
        self.deadlines = []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.deadlines.append((seconds, heavy))
        return True

    def send_response(self, code):
        self.status = code

    def send_header(self, k, v):
        self.headers_sent.append((k, v))

    def end_headers(self):
        pass

    def reply_json(self, code, payload):
        return code, payload


class ReplyJsonNanHeadersAwgStateAndStatusDeadlinesGuardsTests(unittest.TestCase):
    def test_reply_json_never_emits_nan_or_infinity(self):
        """reply_json 收到 NaN / Inf 时不得输出非法 JSON，应替换为 null 并产出合法 RFC 8259 JSON。"""
        fn = _extract_fn('reply_json', {})
        h = _FakeNetHandler()
        fn(h, 200, {'ok': True, 'a': float('nan'), 'b': [1, float('inf'), {'c': float('-inf')}]})
        raw = h.wfile.getvalue().decode('utf-8')
        self.assertNotIn('NaN', raw)
        self.assertNotIn('Infinity', raw)
        parsed = json.loads(raw)
        self.assertEqual(parsed, {'ok': True, 'a': None, 'b': [1, None, {'c': None}]})

    def test_reply_sanitizes_crlf_in_extra_headers(self):
        """reply() 遇到含 CR/LF 的 extra_headers 不得透传注入换行头。"""
        fn = _extract_fn('reply', {'content_policy': lambda: "default-src 'none'"})
        h = _FakeNetHandler()
        fn(h, 200, b'ok', extra_headers=[
            ('X-Good', 'val\r\nSet-Cookie: evil=1'),
            ('Bad\r\nHeader', 'boom'),
        ])
        names = [k for k, _ in h.headers_sent]
        self.assertNotIn('Bad\r\nHeader', names)
        for k, v in h.headers_sent:
            self.assertNotIn('\r', k)
            self.assertNotIn('\n', k)
            self.assertNotIn('\r', v)
            self.assertNotIn('\n', v)

    def test_awg_state_sanitizes_corrupt_meta_and_peers(self):
        """awg_state 须清洗非法 port、非字符串/含控制字符 endpoint 与损坏 peer 字段。"""
        fn = _extract_fn('awg_state', {
            'AWG_META_PATH': Path('/nonexistent/meta.json'),
            'AWG_CTL': '/nonexistent/awgctl',
            'awg_read_json': lambda p, d: {'line': '9', 'port': 999999, 'endpoint': ['bad']},
            'awg_peers': lambda: [
                {'name': 'alice', 'address': '10.66.66.2', 'endpoint': 'a.com\r\n', 'created_at': float('inf')},
                {'name': 123, 'address': None, 'endpoint': {'x': 1}, 'created_at': 1700000000},
            ],
            'awg_installed': lambda: True,
            'awg_active': lambda: True,
        })
        st = fn()
        self.assertEqual(st['line'], '3')
        self.assertEqual(st['port'], '')
        self.assertEqual(st['endpoint'], '')
        self.assertEqual(len(st['peers']), 1)
        self.assertEqual(st['peers'][0]['name'], 'alice')
        self.assertEqual(st['peers'][0]['endpoint'], '')
        self.assertEqual(st['peers'][0]['created_at'], '')
        json.dumps(st, allow_nan=False)

    def test_warp_and_cert_status_extend_deadline_and_sanitize_non_strings(self):
        """_h_get_warp_status 与 _h_get_cert_status 须续期死线，并清洗非字符串 apply_error / server_name。"""
        fn_warp = _extract_fn('_h_get_warp_status', {
            'data_lock': threading.Lock(),
            'data': {'warp_enabled': False, 'warp_rules': [], 'egress_apply_error': ['bad\nerr']},
            'warp_backend_installed': lambda: False,
            'Path': lambda p: SimpleNamespace(read_text=lambda encoding='utf-8': ''),
        })
        h_w = _FakeNetHandler()
        code_w, body_w = fn_warp(h_w, 'warp-status')
        self.assertEqual(code_w, 200)
        self.assertTrue(any(sec >= 30 for sec, _ in h_w.deadlines))
        self.assertEqual(body_w['apply_error'], '')

        fn_cert = _extract_fn('_h_get_cert_status', {
            'meta_path': Path('/tmp/meta.json'),
            'read_meta_file': lambda p: {},
            'cert_status': lambda root, meta, selfheal_state_path='': {
                'ok': True, 'server_name': ['not-a-str'], 'sans': ['a.example.com'], 'common_name': 'a.example.com',
            },
        })
        h_c = _FakeNetHandler()
        code_c, body_c = fn_cert(h_c, 'cert-status')
        self.assertEqual(code_c, 200)
        self.assertTrue(any(sec >= 30 for sec, _ in h_c.deadlines))
        self.assertFalse(body_c['meta_matches_cert'])
        self.assertEqual(body_c['live_server_name'], 'a.example.com')


if __name__ == '__main__':
    unittest.main()
