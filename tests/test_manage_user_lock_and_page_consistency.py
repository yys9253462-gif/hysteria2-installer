"""回归测试：_h_post_manage_user 不得在 data_lock 内写盘，成功不重复重建页面，回滚不留幽灵页面。"""

import copy
import re
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class _TrackableLock:
    def __init__(self):
        self._lock = threading.RLock()
        self.depth = 0

    def __enter__(self):
        self._lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        self.depth -= 1
        self._lock.release()


class ManageUserLockAndPageConsistencyTests(unittest.TestCase):
    def _run_manage(self, form_body: str, sync_ok: bool, initial_users=None):
        lock = _TrackableLock()
        data = {
            'users': copy.deepcopy(initial_users or {'admin_master': {'password': 'master-password'}}),
            'page': 'INITIAL-PAGE',
        }
        save_under_lock = []
        save_calls = []
        regen_calls = []

        def fake_save():
            save_under_lock.append(lock.depth > 0)
            save_calls.append(sorted(data['users'].keys()))

        def fake_regen():
            data['page'] = 'USERS:' + ','.join(sorted(data['users'].keys()))
            regen_calls.append(data['page'])

        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=lock,
            ip_tracker={},
            speed_tracker={},
            global_ip_deny={},
            save_data=fake_save,
            regenerate_page=fake_regen,
            VALID_USER_ID_RE=re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
            QUOTA_RANGE_ERROR=b'quota error',
        )
        fn = extract_method('_h_post_manage_user', ns)
        replies = []
        sent_status = []
        raw = form_body.encode('utf-8')
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            headers={'Content-Length': str(len(raw))},
            rfile=SimpleNamespace(read=lambda n: raw),
            reply=lambda code, payload: replies.append((code, payload)),
            send_response=lambda code: sent_status.append(code),
            send_header=lambda k, v: None,
            end_headers=lambda: None,
            _sync_reality_clients=lambda: sync_ok,
            _responded=False,
        )
        fn(handler, '/tok/')
        return data, replies, sent_status, save_under_lock, save_calls, regen_calls

    def test_delete_sync_failure_never_calls_save_data_while_holding_data_lock(self):
        """删除用户同步失败时，save_data 绝不能在 data_lock 内调用，以免阻塞 /auth 鉴权。"""
        data, replies, _, save_under_lock, save_calls, regen_calls = self._run_manage(
            'action=delete&user_id=alice',
            sync_ok=False,
            initial_users={
                'admin_master': {'password': 'master-password'},
                'alice': {'password': 'alice-password'},
            },
        )
        self.assertEqual(replies[0][0], 503)
        self.assertNotIn('alice', data['users'])
        self.assertIn('alice', data.get('_pending_revocations', []))
        self.assertFalse(any(save_under_lock), f'在持有 data_lock 期间调用了 save_data: {save_under_lock}')
        self.assertEqual(data['page'], 'USERS:admin_master')

    def test_create_sync_failure_does_not_leave_ghost_user_in_rendered_page(self):
        """新建用户同步失败回滚后，data['page'] 不得残留被撤销的幽灵用户。"""
        data, replies, _, save_under_lock, _, _ = self._run_manage(
            'action=create&user_id=bob&duration_days=30&ip_limit=0&traffic_gb=0',
            sync_ok=False,
        )
        self.assertEqual(replies[0][0], 503)
        self.assertNotIn('bob', data['users'])
        self.assertNotIn('bob', data['page'], f'回滚后 page 仍残留已撤销用户: {data["page"]}')
        self.assertFalse(any(save_under_lock))

    def test_create_success_calls_regenerate_page_once_not_twice(self):
        """新建用户成功路径只需重建页面一次，不重复执行两次全量页面重建。"""
        data, _, sent_status, save_under_lock, _, regen_calls = self._run_manage(
            'action=create&user_id=charlie&duration_days=30&ip_limit=0&traffic_gb=0',
            sync_ok=True,
        )
        self.assertEqual(sent_status, [302])
        self.assertIn('charlie', data['users'])
        self.assertEqual(len(regen_calls), 1, f'成功路径重复重建页面次数过多: {len(regen_calls)}')
        self.assertFalse(any(save_under_lock))


if __name__ == '__main__':
    unittest.main()
