"""回归测试：users/set_status 与 users/update 停用立即踢断 Hy2 在线会话、users/update 深拷贝快照、proxy-services/list 快照隔离与 do_GET 损坏 token 返 503。"""

import ast
import copy
import io
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

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
    env['copy'] = copy
    env['AtomicWriteDurabilityError'] = portal.AtomicWriteDurabilityError
    env.update(extra_env)
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'),
        env,
    )
    return env[name]


class _FakeApiHandler:
    def __init__(self, path, payload=None):
        raw = json.dumps(payload).encode('utf-8') if payload is not None else b''
        self.path = path
        self.headers = {'Content-Length': str(len(raw)), 'Authorization': 'Bearer test-key'}
        self.rfile = io.BytesIO(raw)
        self.kicked = []
        self.replies = []

    def check_rate_limit(self, bucket='web'):
        return True

    def verify_api_key(self):
        return True

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        return True

    def _sync_reality_clients(self, core_lock_fd=None):
        return True

    def _kick_old_password_sessions(self, user_id):
        self.kicked.append(user_id)
        return True

    def reply_json(self, code, payload):
        self.replies.append((code, payload))
        return code, payload

    def reply(self, code, body, **kw):
        self.replies.append((code, body))
        return code, body


class ApiDisableKickUpdateSnapshotProxyListAndTokenGuardsTests(unittest.TestCase):
    def test_set_status_and_update_disable_kick_active_hy2_sessions_and_deepcopy_result(self):
        """users/set_status(active=false) 与 users/update(status='disabled') 须踢断 Hy2 活跃会话，且 users/update 返回深拷贝快照。"""
        nested = {'tag': 'v1'}
        data = {
            'users': {
                'alice': {'password': 'p1', 'status': 'active', 'extra': nested},
                'bob': {'password': 'p2', 'status': 'active'},
            }
        }
        fn_post = _extract_method('do_POST', {
            'data_lock': threading.Lock(),
            'data': data,
            'save_data': Mock(),
            'regenerate_page': Mock(),
            'rotate_user_view_key_on_change': lambda old, new: None,
            'password_taken': lambda m, p, uid: False,
            'VALID_USER_ID_RE': __import__('re').compile(r'^[A-Za-z0-9_.-]{1,64}$'),
            'RESERVED_USER_IDS': set(),
        })

        # 1) users/set_status 停用 bob -> 必须调用 _kick_old_password_sessions('bob')
        h1 = _FakeApiHandler('/api/v1/users/set_status', {'user_id': 'bob', 'active': False})
        st1, body1 = fn_post(h1)
        self.assertEqual(st1, 200, body1)
        self.assertEqual(h1.kicked, ['bob'])

        # 2) users/update 停用 alice -> 必须踢断会话，且返回快照的嵌套对象与内存中对象隔离
        h2 = _FakeApiHandler('/api/v1/users/update', {'user_id': 'alice', 'status': 'disabled'})
        st2, body2 = fn_post(h2)
        self.assertEqual(st2, 200, body2)
        self.assertEqual(h2.kicked, ['alice'])
        self.assertIsNot(body2['user']['extra'], nested)

    def test_api_proxy_services_list_detaches_dicts_and_do_get_rejects_corrupt_portal_token(self):
        """GET /api/v1/proxy-services/list 须锁内浅拷贝字典并过滤脏项；do_GET 遇到含换行/斜杠 token 返 503。"""
        orig = {'id': 'p1', 'type': 'socks5', 'port': 1080}
        data = {'proxy_services': [orig, None, 'dirty'], 'token': 'bad/token\r\n'}
        fn_get = _extract_method('do_GET', {
            'data_lock': threading.Lock(),
            'data': data,
            'proxy_services': lambda d: list(d.get('proxy_services', [])),
            'meta_path': Path('/nonexistent/meta.json'),
            'read_meta_file': lambda p: {'server_name': 'node.example.com'},
            'meta_display_host': lambda m: 'node.example.com',
            'gost_status': lambda: True,
        })

        h1 = _FakeApiHandler('/api/v1/proxy-services/list')
        st1, body1 = fn_get(h1)
        self.assertEqual(st1, 200, body1)
        self.assertEqual(len(body1['services']), 1)
        self.assertIsNot(body1['services'][0], orig)

        h2 = _FakeApiHandler('/bad/token\r\n/')
        st2, body2 = fn_get(h2)
        self.assertEqual(st2, 503, body2)


if __name__ == '__main__':
    unittest.main()
