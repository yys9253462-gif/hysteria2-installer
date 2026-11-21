"""回归测试：_h_post_manage_user 落盘失败必须完整回滚内存（创建与删除）且 302 带 Connection: close 安全头。"""

import io
import re
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class _FakeHandler:
    def __init__(self, body: bytes, sync_ok: bool = True):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.sync_ok = sync_ok
        self.sync_calls = 0
        self.reply_result = None
        self.sent_status = None
        self.sent_headers = []
        self._responded = False

    def is_authenticated(self):
        return True

    def _sync_reality_clients(self):
        self.sync_calls += 1
        return self.sync_ok

    def reply(self, code, body, mime='text/plain; charset=utf-8', **kw):
        self.reply_result = (code, body)
        return code, body

    def send_response(self, code):
        self.sent_status = code

    def send_header(self, k, v):
        self.sent_headers.append((k, v))

    def end_headers(self):
        pass


class ManageUserSaveRollbackAndHeadersTests(unittest.TestCase):
    def _build_fn(self, data, save_mock, ip_tracker=None, speed_tracker=None, global_ip_deny=None):
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            save_data=save_mock,
            regenerate_page=mock.Mock(),
            ip_tracker=ip_tracker if ip_tracker is not None else {},
            speed_tracker=speed_tracker if speed_tracker is not None else {},
            global_ip_deny=global_ip_deny if global_ip_deny is not None else {},
            QUOTA_RANGE_ERROR='配额超限'.encode('utf-8'),
            VALID_USER_ID_RE=re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
        )
        return extract_method('_h_post_manage_user', ns)

    def test_create_save_failure_rolls_back_new_user_in_memory(self):
        """创建用户 save_data 抛 OSError 时，必须回滚内存中的新用户，不得残留幽灵账号。"""
        data = {'token': 'tok', 'users': {}}
        save_mock = mock.Mock(side_effect=OSError('disk full'))
        fn = self._build_fn(data, save_mock)
        h = _FakeHandler(b'action=create&user_id=alice&password=secret123&duration_days=30')
        code, _ = fn(h, '/tok/')
        self.assertEqual(code, 500)
        save_mock.assert_called_once()
        self.assertNotIn('alice', data['users'], 'save_data 失败后新用户仍残留在内存中')
        self.assertEqual(h.sync_calls, 0)

    def test_delete_save_failure_rolls_back_user_and_trackers(self):
        """删除用户 save_data 抛 OSError 时，必须恢复用户、pending_revocations 及运行态追踪器。"""
        data = {
            'token': 'tok',
            'users': {'bob': {'password': 'pw', 'status': 'active'}},
            'usage_meter': {'totals': {'bob': {'hysteria': 100}}},
        }
        ip_tracker = {'bob': {'1.2.3.4': 123}}
        speed_tracker = {'bob': [(1.0, 10, 20)]}
        global_ip_deny = {'bob': {'1.2.3.4': 999}}
        save_mock = mock.Mock(side_effect=OSError('disk full'))
        fn = self._build_fn(data, save_mock,
                            ip_tracker=ip_tracker, speed_tracker=speed_tracker,
                            global_ip_deny=global_ip_deny)
        h = _FakeHandler(b'action=delete&user_id=bob')
        code, _ = fn(h, '/tok/')
        self.assertEqual(code, 500)
        save_mock.assert_called_once()
        self.assertIn('bob', data['users'], '删除落盘失败后用户未被还原')
        self.assertNotIn('bob', data.get('_pending_revocations', []))
        self.assertIn('bob', ip_tracker)
        self.assertIn('bob', speed_tracker)
        self.assertIn('bob', global_ip_deny)

    def test_success_redirect_sets_connection_close_and_security_headers(self):
        """创建成功 302 跳转必须带 Connection: close 与安全响应头，防止门户连接挂起。"""
        data = {'token': 'tok', 'users': {}}
        fn = self._build_fn(data, mock.Mock())
        h = _FakeHandler(b'action=create&user_id=carol&password=secret123&duration_days=30')
        fn(h, '/tok/')
        self.assertEqual(h.sent_status, 302)
        hdrs = {k.lower(): v for k, v in h.sent_headers}
        self.assertEqual(hdrs.get('connection'), 'close')
        self.assertEqual(hdrs.get('x-content-type-options'), 'nosniff')
        self.assertEqual(hdrs.get('x-frame-options'), 'DENY')


if __name__ == '__main__':
    unittest.main()
