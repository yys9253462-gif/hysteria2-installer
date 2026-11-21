"""回归测试：REST API users/delete 并发回滚保留与 users/create、users/update 密码控制字符拦截。"""
import ast
import copy
import io
import json
import re
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def _extract_api_post(data, save_data):
    tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
    branch = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.If) and ast.unparse(n.test) == "self.path.startswith('/api/v1/')"
    )
    fn = ast.parse('def handle(self):\n    pass').body[0]
    fn.body = [copy.deepcopy(branch)]
    env = dict(
        portal.__dict__,
        data=data,
        data_lock=threading.RLock(),
        ip_tracker={'bob': {'1.2.3.4': 10.0}},
        speed_tracker={'bob': [(1.0, 2, 3)]},
        global_ip_deny={'bob': {'1.2.3.4': 9999999999}},
        VALID_USER_ID_RE=re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
        save_data=save_data,
        regenerate_page=Mock(),
        apply_access=Mock(return_value=True),
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                 '<api-users-guards>', 'exec'), env)
    return env['handle']


def _call_api(fn, path, payload):
    body = json.dumps(payload).encode('utf-8')
    h = SimpleNamespace(
        path=path,
        headers={'Content-Length': str(len(body))},
        rfile=io.BytesIO(body),
        verify_api_key=lambda: True,
        check_rate_limit=lambda bucket='api': True,
        _sync_reality_clients=lambda: True,
        _kick_old_password_sessions=Mock(),
        reply=lambda status, raw: (status, raw),
        reply_json=lambda status, obj: (status, obj),
    )
    return fn(h)


class ApiUsersRollbackAndPasswordGuardsTests(unittest.TestCase):
    def test_api_delete_save_rollback_preserves_concurrent_pending_and_other_meter(self):
        """POST /api/v1/users/delete 落盘失败回滚时，不得覆写并发新增的待撤销项与其它用户计量。"""
        data = {
            'users': {
                'bob': {'password': 'pw1', 'status': 'active'},
                'alice': {'password': 'pw2', 'status': 'active'},
            },
            'usage_meter': {
                'totals': {'bob': {'hysteria': 100}, 'alice': {'hysteria': 50}},
                'adjustments': {'bob': {'hysteria': 10}, 'alice': {'hysteria': 5}},
            },
        }

        def concurrent_fail_save():
            data['_pending_revocations'] = sorted(set(data.get('_pending_revocations', [])) | {'charlie'})
            data['usage_meter']['totals']['alice'] = {'hysteria': 888}
            data['usage_meter']['adjustments']['alice'] = {'hysteria': 66}
            raise OSError('disk full')

        fn = _extract_api_post(data, concurrent_fail_save)
        status, payload = _call_api(fn, '/api/v1/users/delete', {'user_id': 'bob'})
        self.assertEqual(status, 503)
        self.assertFalse(payload['ok'])
        self.assertIn('bob', data['users'])
        self.assertEqual(data.get('_pending_revocations'), ['charlie'])
        self.assertEqual(data['usage_meter']['totals']['bob'], {'hysteria': 100})
        self.assertEqual(data['usage_meter']['adjustments']['bob'], {'hysteria': 10})
        self.assertEqual(data['usage_meter']['totals']['alice'], {'hysteria': 888})
        self.assertEqual(data['usage_meter']['adjustments']['alice'], {'hysteria': 66})

    def test_api_create_and_update_reject_control_chars_in_password(self):
        """POST /api/v1/users/create 与 users/update 必须以 400 拒绝含控制字符的密码。"""
        for bad_pwd in ('abc\rdef', 'abc\ndef', 'abc\x00def', 'abc\x7fdef'):
            data = {'users': {'u1': {'password': 'good_password', 'status': 'active'}}}
            save_mock = Mock()
            fn = _extract_api_post(data, save_mock)

            st_create, _ = _call_api(fn, '/api/v1/users/create', {'user_id': 'u2', 'password': bad_pwd})
            self.assertEqual(st_create, 400, f'users/create 应拒绝控制字符密码 {bad_pwd!r}')
            self.assertNotIn('u2', data['users'])

            st_update, _ = _call_api(fn, '/api/v1/users/update', {'user_id': 'u1', 'password': bad_pwd})
            self.assertEqual(st_update, 400, f'users/update 应拒绝控制字符密码 {bad_pwd!r}')
            self.assertEqual(data['users']['u1']['password'], 'good_password')
            save_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
