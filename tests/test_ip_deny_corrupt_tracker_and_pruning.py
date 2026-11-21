"""回归测试：users/ip-deny 容忍损坏 ip_tracker 时间戳，并在 global_ip_deny 膨胀时回收已过期条目。"""

import ast
import copy
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _run_ip_deny(params, ip_tracker, global_ip_deny, now_ts=2000.0):
    tree = ast.parse(PORTAL.read_text(encoding='utf-8'))
    branch = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.If)
        and isinstance(n.test, ast.Compare)
        and any(isinstance(v, ast.Constant) and v.value == 'users/ip-deny' for v in n.test.comparators)
    )
    fn = ast.parse('def handle(self, params):\n    pass').body[0]
    fn.body = copy.deepcopy(branch.body)
    kicked_calls = []
    env = dict(portal.__dict__)
    env.update({
        'data_lock': threading.RLock(),
        'global_ip_deny': global_ip_deny,
        'ip_tracker': ip_tracker,
        'portal_path': Path('/tmp/portal.json'),
        'live_online_ips': lambda uid: set(),
        'kick_hy2_users': lambda root, ids: (kicked_calls.append(list(ids)) or True),
        '_log_ignored': lambda *a: None,
        'time': type('T', (), {'time': staticmethod(lambda: now_ts)})(),
    })
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<ip_deny>', 'exec'), env)

    class Handler:
        def reply_json(self, status, payload):
            return status, payload

    status, payload = env['handle'](Handler(), params)
    return status, payload, kicked_calls


class IpDenyCorruptTrackerAndPruningTests(unittest.TestCase):
    def test_corrupt_ip_tracker_entries_do_not_crash_ip_deny(self):
        # ip_tracker 中包含非数字时间戳或非字典条目时不能抛 TypeError/AttributeError
        denies = {}
        status, payload, kicked = _run_ip_deny(
            {'user_id': 'alice', 'ips': ['198.51.100.7'], 'ttl': 120},
            ip_tracker={'alice': {'198.51.100.7': 'corrupt-ts', '198.51.100.8': None, '198.51.100.9': True}},
            global_ip_deny=denies,
            now_ts=2000.0,
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload['ok'])
        self.assertEqual(kicked, [])

        status2, payload2, _ = _run_ip_deny(
            {'user_id': 'bob', 'ips': ['198.51.100.7'], 'ttl': 120},
            ip_tracker={'bob': ['not-a-dict']},
            global_ip_deny=denies,
            now_ts=2000.0,
        )
        self.assertEqual(status2, 200)
        self.assertTrue(payload2['ok'])

    def test_expired_global_ip_deny_entries_pruned_when_table_exceeds_threshold(self):
        denies = {f'stale_{i}': {'198.51.100.1': 100.0} for i in range(4100)}
        status, payload, _ = _run_ip_deny(
            {'user_id': 'fresh_user', 'ips': ['198.51.100.9'], 'ttl': 300},
            ip_tracker={},
            global_ip_deny=denies,
            now_ts=2000.0,
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload['ok'])
        self.assertIn('fresh_user', denies)
        self.assertLess(len(denies), 10, '超过阈值后未清理已过期的 global_ip_deny 条目')


if __name__ == '__main__':
    unittest.main()
