"""Isolated synthetic regressions; never import portal or invoke real services."""
import ast
import hashlib
import hmac
import secrets
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'portal.py'
TREE = ast.parse(SOURCE.read_text(encoding='utf-8'))
ENV = dict(hashlib=hashlib, hmac=hmac, secrets=secrets, time=time)
for node in TREE.body:
    if isinstance(node, ast.FunctionDef) and node.name in {
        'user_view_key', 'rotate_user_view_key_on_change', 'user_share_available',
        'user_access_allowed', 'user_access_denial'
    }:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), ENV)


class Lifecycle(unittest.TestCase):
    def test_legacy_links_survive_same_value_retry(self):
        before = {'password': 'synthetic', 'status': 'active'}
        after = dict(before)
        ENV['rotate_user_view_key_on_change'](before, after)
        self.assertNotIn('view_nonce', after)
        self.assertEqual(ENV['user_view_key']('test', 'u'),
                         ENV['user_view_key']('test', 'u', after.get('view_nonce', '')))

    def test_password_change_revokes_and_retry_preserves(self):
        before = {'password': 'synthetic', 'status': 'active'}
        after = dict(before, password='replacement')
        ENV['rotate_user_view_key_on_change'](before, after)
        key = ENV['user_view_key']('test', 'u', after['view_nonce'])
        self.assertNotEqual(key, ENV['user_view_key']('test', 'u'))
        retry = dict(after)
        ENV['rotate_user_view_key_on_change'](after, retry)
        self.assertEqual(after, retry)

    def test_disable_enable_cannot_revive_old_key(self):
        before = {'password': 'synthetic', 'status': 'active', 'view_nonce': 'old'}
        after = dict(before, status='disabled')
        ENV['rotate_user_view_key_on_change'](before, after)
        self.assertNotEqual(after['view_nonce'], 'old')
        enabled = dict(after, status='active')
        ENV['rotate_user_view_key_on_change'](after, enabled)
        self.assertEqual(after['view_nonce'], enabled['view_nonce'])

    def test_status_expiry_and_quota(self):
        available = ENV['user_share_available']
        self.assertTrue(available({}, 100))
        for user in ({'status': 'disabled'}, {'expires_at': 100},
                     {'expires_at': 99}, {'limit_bytes': 10, 'used_bytes': 10},
                     {'limit_bytes': 10, 'used_bytes': 11}):
            self.assertFalse(available(user, 100))
        self.assertTrue(available({'expires_at': 101, 'limit_bytes': 10, 'used_bytes': 9}, 100))

    def test_auth_header_boundary_before_rate_bucket(self):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "self.path == '/auth'")
        guard = branch.body[0]
        class Handler:
            client_address = ('127.0.0.1', 1234)
            headers = {}
            def reply_json(self, status, payload):
                return payload['ok']
        handler = Handler()
        env = {'self': handler}
        fn = ast.FunctionDef(name='guard', args=ast.arguments(posonlyargs=[], args=[],
            kwonlyargs=[], kw_defaults=[], defaults=[]), body=[guard], decorator_list=[])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     'guard', 'exec'), env)
        self.assertIsNone(env['guard']())
        for name in ('X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'Forwarded'):
            handler.headers = {name: ''}
            self.assertIs(env['guard'](), False)
        handler.headers = {}
        handler.client_address = ('198.51.100.1', 1234)
        self.assertIs(env['guard'](), False)

    def test_master_create_guard_executes_before_business_code(self):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "sub == 'users/create'")
        # 保留名校验从「ID 格式」里拆开了，两道守卫都要跑。
        guards = [branch.body[1], branch.body[2]]
        class Handler:
            def reply_json(self, status, payload):
                return status
        import re
        env = dict(self=Handler(), user_id='admin_master',
                   RESERVED_USER_IDS=frozenset({'admin_master', 'placeholder'}),
                   VALID_USER_ID_RE=re.compile(r'^[a-zA-Z0-9_.-]{1,64}$'))
        fn = ast.FunctionDef(name='guard', args=ast.arguments(posonlyargs=[], args=[],
            kwonlyargs=[], kw_defaults=[], defaults=[]), body=guards, decorator_list=[])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     'guard', 'exec'), env)
        self.assertEqual(env['guard'](), 400)
        env['user_id'] = 'ordinary'
        self.assertIsNone(env['guard']())


if __name__ == '__main__':
    unittest.main()
