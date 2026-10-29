"""鉴权与速率缓存的边界回归；不启动服务或修改节点。"""
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

TREE = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))


class AuthBoundaryTests(unittest.TestCase):
    def auth(self, users, password='pw', now=100.5):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "self.path == '/auth'")
        fn = ast.parse('def handle(self):\n    pass').body[0]
        fn.body = [copy.deepcopy(branch)]
        env = dict(portal.__dict__, data={'users': users}, data_lock=threading.RLock(),
                   ip_tracker={}, live_online_ips=lambda uid: set(),
                   reality_live_ips=lambda uid: set())
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     '<auth-boundary>', 'exec'), env)
        body = json.dumps({'auth': password, 'addr': '198.51.100.2:1234'}).encode()
        handler = SimpleNamespace(path='/auth', client_address=('127.0.0.1', 1234),
            headers={'Content-Length': str(len(body))}, rfile=io.BytesIO(body),
            auth_rate_limited=lambda: False, record_auth_failure=Mock(),
            reply_json=lambda status, payload: payload)
        with patch.object(time, 'time', return_value=now):
            return env['handle'](handler)

    def test_corrupt_unrelated_user_does_not_break_valid_auth(self):
        for corrupt in (None, [], 'broken', 7):
            with self.subTest(corrupt=corrupt):
                self.assertTrue(self.auth({'bad': corrupt, 'valid': {'password': 'pw'}})['ok'])

    def test_expiry_matches_shared_admission(self):
        for expiry in ('200', '99', 'invalid', float('nan'), 100.2, None, 0):
            with self.subTest(expiry=expiry):
                user = {'password': 'pw', 'expires_at': expiry}
                self.assertEqual(self.auth({'u': user})['ok'],
                                 portal.user_access_allowed(user, 100.5))

    def test_invalid_persisted_limits_deny_without_exception(self):
        for field in ('limit_bytes', 'used_bytes', 'ip_limit'):
            for value in ('invalid', None, float('inf')):
                with self.subTest(field=field, value=value):
                    user = {'password': 'pw', 'limit_bytes': 10, field: value}
                    self.assertFalse(self.auth({'u': user})['ok'])

    def test_missing_or_empty_password_never_authenticates(self):
        for user in ({}, {'password': ''}, {'password': None}, {'password': 123}):
            with self.subTest(user=user):
                for supplied in ('', 'None', '123'):
                    self.assertFalse(self.auth({'u': user}, supplied)['ok'])

    def test_password_whitespace_is_significant(self):
        self.assertTrue(self.auth({'u': {'password': ' pw '}}, ' pw ')['ok'])
        self.assertFalse(self.auth({'u': {'password': 'pw'}}, ' pw ')['ok'])


class SpeedBoundaryTests(unittest.TestCase):
    def test_orphan_speed_entry_is_removed_before_aggregation(self):
        node = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
                    and n.name == '_h_get_traffic_speed')
        tracker = {'deleted': {'hysteria': (100, 99, 88)},
                   'live': {'hysteria': (100, 3, 4)}}
        env = dict(portal.__dict__, data={'users': {'live': {'used_bytes': 17}}},
                   data_lock=threading.RLock(), speed_tracker=tracker,
                   usage_hot_summary=lambda uid: {}, SPEED_WINDOW_SECONDS=15)
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<speed-boundary>', 'exec'), env)
        handler = SimpleNamespace(is_authenticated=lambda: True,
                                  reply_json=lambda status, payload: payload)
        with patch.object(time, 'monotonic', return_value=101):
            result = env['_h_get_traffic_speed'](handler, '')
        self.assertEqual(set(result['users']), {'live'})
        self.assertEqual(result['total_used_bytes'], 17)
        self.assertEqual((result['node_tx'], result['node_rx']), (3, 4))
        self.assertNotIn('deleted', tracker)


if __name__ == '__main__':
    unittest.main()
