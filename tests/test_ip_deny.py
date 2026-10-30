"""跨节点统一设备上限：控制台下发的拦截 IP（2026-10-30）。"""
import ast
import copy
import io
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import portal  # noqa: E402
from test_round2_fixes import PortalServer  # noqa: E402

TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


class ParseTests(unittest.TestCase):
    def test_valid_and_normalized(self):
        uid, entries = portal.parse_ip_deny({'user_id': 'sub_a', 'ips': ['198.51.100.7', '2001:db8::1'], 'ttl': 600}, 1000)
        self.assertEqual(uid, 'sub_a')
        self.assertEqual(entries, {'198.51.100.7': 1600, '2001:db8::1': 1600})

    def test_rejects_bad_input(self):
        for params in ({'user_id': 'bad id', 'ips': []}, {'user_id': 'u', 'ips': 'x'},
                       {'user_id': 'u', 'ips': ['not-an-ip']}, {'user_id': 'u', 'ips': [], 'ttl': 5},
                       {'user_id': 'u', 'ips': ['1.1.1.1'] * 65}):
            with self.assertRaises(ValueError):
                portal.parse_ip_deny(params, 0)

    def test_expired_entries_drop_out(self):
        table = {'u': {'1.1.1.1': 100, '2.2.2.2': 300}}
        self.assertEqual(portal.active_ip_deny(table, 'u', 200), {'2.2.2.2'})
        self.assertEqual(portal.active_ip_deny(table, 'u', 400), set())
        self.assertNotIn('u', table, '全部过期后整条清掉，内存不会只增不减')


class AuthDenyTests(unittest.TestCase):
    def auth(self, deny, client='198.51.100.2'):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "self.path == '/auth'")
        fn = ast.parse('def handle(self):\n    pass').body[0]
        fn.body = [copy.deepcopy(branch)]
        users = {'sub_a': {'password': 'pw', 'status': 'active', 'expires_at': 10**10, 'ip_limit': 3}}
        env = dict(portal.__dict__, data={'users': users}, data_lock=threading.RLock(),
                   ip_tracker={}, global_ip_deny=deny, live_online_ips=lambda uid: set(),
                   reality_live_ips=lambda uid: set())
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<ip-deny>', 'exec'), env)
        body = json.dumps({'auth': 'pw', 'addr': client + ':1234'}).encode()
        handler = SimpleNamespace(path='/auth', client_address=('127.0.0.1', 1234),
            headers={'Content-Length': str(len(body))}, rfile=io.BytesIO(body),
            auth_rate_limited=lambda: False, record_auth_failure=Mock(),
            reply_json=lambda status, payload: payload)
        with patch.object(time, 'time', return_value=1000):
            return env['handle'](handler)

    def test_denied_ip_is_refused(self):
        out = self.auth({'sub_a': {'198.51.100.2': 2000}})
        self.assertFalse(out.get('ok'), out)

    def test_other_ip_and_expired_deny_still_pass(self):
        self.assertTrue(self.auth({'sub_a': {'203.0.113.9': 2000}}).get('ok'))
        self.assertTrue(self.auth({'sub_a': {'198.51.100.2': 999}}).get('ok'), '过期的拦截不能再生效')


class ApiTests(PortalServer):
    def api(self, payload):
        status, body = self.request('/api/v1/users/ip-deny', payload,
                                    {'Authorization': 'Bearer ' + self.data['api_key']})
        return status, json.loads(body)

    def test_set_and_clear(self):
        status, body = self.api({'user_id': 'sub_x', 'ips': ['198.51.100.7'], 'ttl': 120})
        self.assertEqual(status, 200, body)
        self.assertEqual(body['denied'], ['198.51.100.7'])
        status, body = self.api({'user_id': 'sub_x', 'ips': []})
        self.assertEqual((status, body['denied']), (200, []))
        status, body = self.api({'user_id': 'sub_x', 'ips': ['nope']})
        self.assertEqual(status, 400)

    def test_requires_api_key(self):
        self.assertEqual(self.request('/api/v1/users/ip-deny', {'user_id': 'u', 'ips': []})[0], 401)


if __name__ == '__main__':
    unittest.main()
