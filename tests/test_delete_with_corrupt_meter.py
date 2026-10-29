"""删除用户时损坏的计量容器不能中断注销，否则内存已删、磁盘未存、访问未撤销。"""
import ast
import copy
import io
import json
from pathlib import Path
import re
import sys
import threading
import unittest
from types import SimpleNamespace
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SOURCE = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)
BAD_METERS = ({'totals': None}, {'totals': []}, {'totals': 'broken'}, ['broken'])


def api_delete_branch():
    return next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and any(isinstance(v, ast.Constant) and v.value == 'users/delete'
                        for v in n.test.comparators))


def run_api_delete(usage_meter, user='probe'):
    branch = api_delete_branch()
    fn = ast.parse('def delete(self, params):\n    pass').body[0]
    fn.body = copy.deepcopy(branch.body)
    state = {'users': {user: {'password': 'test-only'},
                       'admin_master': {'password': 'master-test-only'}}}
    if usage_meter is not None:
        state['usage_meter'] = copy.deepcopy(usage_meter)
    calls = []
    env = dict(data=state, data_lock=threading.RLock(),
               regenerate_page=lambda: calls.append('page'),
               reality_registry=lambda _: calls.append('registry'),
               VALID_USER_ID_RE=re.compile(r'^[a-z_]+$'),
               MASTER_USER_ID='admin_master',
               ip_tracker={user: {'1.1.1.1'}} if user != 'admin_master' else {},
               speed_tracker={user: [1]} if user != 'admin_master' else {},
               drop_meter_totals=portal.drop_meter_totals,
               pending_revocations=portal.pending_revocations,
               apply_access=lambda ids: calls.append(('revoke', ids)) or True)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                 '<delete>', 'exec'), env)

    class Handler:
        def reply_json(self, status, body):
            return status, body

    status, _ = env['delete'](Handler(), {'user_id': user})
    return status, state, env, calls


def run_web_delete(usage_meter):
    state = {'users': {'probe': {'password': 'test-only'}},
             'reality_config': {'port': 8443}}
    if usage_meter is not None:
        state['usage_meter'] = copy.deepcopy(usage_meter)
    calls = []
    ns = dict(portal.__dict__, data=state, data_lock=threading.RLock(),
              ip_tracker={'probe': {'1.1.1.1'}}, speed_tracker={'probe': [1]},
              drop_meter_totals=portal.drop_meter_totals,
              pending_revocations=portal.pending_revocations,
              save_data=lambda: calls.append('save'),
              regenerate_page=lambda: calls.append('page'),
              MASTER_USER_ID='admin_master',
              VALID_USER_ID_RE=re.compile(r'^[a-z_]+$'))
    node = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
                and n.name == '_h_post_manage_user')
    exec(compile(ast.Module(body=[copy.deepcopy(node)], type_ignores=[]),
                 '<web-delete>', 'exec'), ns)

    body = urlencode({'action': 'delete', 'user_id': 'probe'}).encode()

    class Handler:
        headers = {'Content-Length': str(len(body))}
        rfile = io.BytesIO(body)
        status = None

        def is_authenticated(self):
            return True

        def reply(self, status, payload):
            return status

        def _sync_reality_clients(self):
            calls.append('sync')
            return True

        def send_response(self, status):
            self.status = status

        def send_header(self, *args):
            pass

        def end_headers(self):
            pass

    handler = Handler()
    result = ns['_h_post_manage_user'](handler, '/test-token/')
    # 成功分支走 302 重定向（send_response），不返回状态码。
    return handler.status if handler.status is not None else result, state, calls


class DeleteWithCorruptMeterTests(unittest.TestCase):
    def test_corrupt_meter_does_not_abort_revocation(self):
        for bad in BAD_METERS:
            with self.subTest(bad=bad):
                status, state, env, calls = run_api_delete(bad)
                self.assertEqual(status, 200)
                self.assertNotIn('probe', state['users'])
                self.assertEqual(state['_pending_revocations'], ['probe'])
                self.assertIn(('revoke', ['probe']), calls)
                self.assertEqual(env['ip_tracker'], {})
                self.assertEqual(env['speed_tracker'], {})
                # 损坏的计量容器保留原件，不能被删除顺手清空或改写。
                self.assertEqual(state['usage_meter'], bad)

    def test_missing_meter_still_deletes(self):
        status, state, env, calls = run_api_delete(None)
        self.assertEqual(status, 200)
        self.assertNotIn('probe', state['users'])
        self.assertNotIn('usage_meter', state)
        self.assertIn(('revoke', ['probe']), calls)

    def test_healthy_meter_still_drops_totals(self):
        status, state, env, calls = run_api_delete(
            {'totals': {'probe': {'hysteria': 5}, 'keep': {'hysteria': 1}}})
        self.assertEqual(status, 200)
        self.assertEqual(state['usage_meter']['totals'], {'keep': {'hysteria': 1}})

    def test_master_account_is_still_protected(self):
        status, state, env, calls = run_api_delete(
            {'totals': {'admin_master': {'hysteria': 5}}}, user='admin_master')
        self.assertEqual(status, 400)
        self.assertIn('admin_master', state['users'])
        self.assertFalse([c for c in calls if isinstance(c, tuple)])

    def test_web_delete_tolerates_corrupt_meter(self):
        for bad in BAD_METERS:
            with self.subTest(bad=bad):
                status, state, calls = run_web_delete(bad)
                self.assertEqual(status, 302)
                self.assertNotIn('probe', state['users'])
                self.assertIn('sync', calls)
                self.assertEqual(state['usage_meter'], bad)


if __name__ == '__main__':
    unittest.main()
