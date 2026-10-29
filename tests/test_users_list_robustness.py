"""users/list 遇到损坏的用户记录或 ip_tracker 残留格式不能整表 500。"""
import ast
import copy
from pathlib import Path
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
HELPERS = {'users_list_rows', 'active_online_ips', 'users_list_entry'}


def branch(value):
    return next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and any(isinstance(v, ast.Constant) and v.value == value
                        for v in n.test.comparators))


def load(extra_globals=None):
    nodes = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in HELPERS]
    nodes.append(branch('users/list'))
    body = copy.deepcopy(nodes[:-1])
    fn = ast.parse('def listing(self):\n    pass').body[0]
    fn.body = copy.deepcopy(nodes[-1].body)
    env = dict(extra_globals or {})
    exec(compile(ast.fix_missing_locations(ast.Module(body=body + [fn], type_ignores=[])),
                 '<users-list>', 'exec'), env)
    return env


class UsersListRobustnessTests(unittest.TestCase):
    def run_listing(self, users, tracker, summary=None):
        env = load({'time': time, 'IP_TIMEOUT_SECONDS': 180,
                    'data_lock': threading.RLock(), 'ip_tracker': tracker,
                    'data': {'users': users},
                    'usage_list_summary': summary or (lambda uid: (
                        {'measured_bytes': None, 'measurement_ok': False,
                         'legacy_auth_value': 0}, [], {})),
                    'user_access_allowed': lambda info, now=0: True})

        class Handler:
            def reply_json(self, status, payload):
                return status, payload

        return env['listing'](Handler())

    def test_corrupt_user_record_is_skipped_not_fatal(self):
        status, body = self.run_listing(
            {'good': {'used_bytes': 5}, 'bad': 'oops', 'none': None}, {})
        self.assertEqual(status, 200)
        self.assertEqual([u['user_id'] for u in body['users']], ['good'])

    def test_corrupt_tracker_does_not_break_listing(self):
        for tracker in ({'u': ['1.1.1.1']}, {'u': '1.1.1.1'}, {'u': None}, {'u': 5}, ['broken']):
            with self.subTest(tracker=tracker):
                status, body = self.run_listing({'u': {'used_bytes': 0}}, tracker)
                self.assertEqual(status, 200)
                self.assertEqual(body['users'][0]['online_ips'], [])

    def test_corrupt_tracker_values_are_skipped(self):
        now = int(time.time())
        status, body = self.run_listing(
            {'u': {'used_bytes': 0}},
            {'u': {'1.1.1.1': now, '2.2.2.2': True, '3.3.3.3': 'x', '4.4.4.4': now - 10**6}})
        self.assertEqual(status, 200)
        self.assertEqual([row['ip'] for row in body['users'][0]['online_ips']], ['1.1.1.1'])

    def test_whole_user_table_corrupt_returns_empty_list(self):
        for users in (['broken'], None, 'oops', 7):
            with self.subTest(users=users):
                status, body = self.run_listing(users, {})
                self.assertEqual(status, 200)
                self.assertEqual(body['users'], [])

    def test_healthy_rows_keep_both_field_names(self):
        now = int(time.time())
        status, body = self.run_listing(
            {'u': {'used_bytes': 7, 'limit_bytes': 9, 'status': 'active', 'ip_limit': 2}},
            {'u': {'1.1.1.1': now}})
        self.assertEqual(status, 200)
        row = body['users'][0]
        self.assertEqual((row['used_bytes'], row['traffic_used_bytes']), (7, 7))
        self.assertEqual((row['limit_bytes'], row['traffic_limit_bytes']), (9, 9))
        self.assertEqual(row['ip_limit'], 2)
        self.assertEqual(row['online_ips'][0]['ip'], '1.1.1.1')
        self.assertTrue(row['active'])


if __name__ == '__main__':
    unittest.main()
