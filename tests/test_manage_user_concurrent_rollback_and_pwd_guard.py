"""回归测试：_h_post_manage_user 删除回滚保留并发变更（pending/meter）与密码控制字符拦截。"""
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
    def __init__(self, body: bytes):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.reply_result = None

    def is_authenticated(self):
        return True

    def _sync_reality_clients(self):
        return True

    def reply(self, code, body, mime='text/plain; charset=utf-8', **kw):
        self.reply_result = (code, body)
        return code, body


class ManageUserConcurrentRollbackAndPwdGuardTests(unittest.TestCase):
    def _build_fn(self, data, save_mock):
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            save_data=save_mock,
            regenerate_page=mock.Mock(),
            ip_tracker={'bob': {'1.2.3.4': 10}},
            speed_tracker={'bob': [(1.0, 2, 3)]},
            global_ip_deny={'bob': {'1.2.3.4': 20}},
            QUOTA_RANGE_ERROR='配额超限'.encode('utf-8'),
            VALID_USER_ID_RE=re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
        )
        return extract_method('_h_post_manage_user', ns)

    def test_delete_save_rollback_preserves_concurrent_pending_and_other_user_meter(self):
        """删除落盘失败回滚时，只回滚当前用户条目，不得覆盖并发新增的待撤销项与其它用户计量。"""
        data = {
            'token': 'tok',
            'users': {
                'bob': {'password': 'pw1', 'status': 'active'},
                'alice': {'password': 'pw2', 'status': 'active'},
            },
            'usage_meter': {
                'totals': {
                    'bob': {'hysteria': 100},
                    'alice': {'hysteria': 50},
                },
                'adjustments': {
                    'bob': {'hysteria': 10},
                    'alice': {'hysteria': 5},
                },
            },
        }

        def concurrent_fail_save():
            # 模拟 save_data 期间并发删除了另一个用户并更新了 alice 的计量
            data['_pending_revocations'] = sorted(set(data.get('_pending_revocations', [])) | {'charlie'})
            data['usage_meter']['totals']['alice'] = {'hysteria': 999}
            data['usage_meter']['adjustments']['alice'] = {'hysteria': 77}
            raise OSError('disk full')

        fn = self._build_fn(data, concurrent_fail_save)
        code, _ = fn(_FakeHandler(b'action=delete&user_id=bob'), '/tok/')
        self.assertEqual(code, 500)
        self.assertIn('bob', data['users'])
        # bob 的撤销项应撤回，但并发加入的 charlie 必须保留
        self.assertEqual(data.get('_pending_revocations'), ['charlie'])
        # bob 的用量与调整恢复，且 alice 的最新并发计量不得被旧快照覆写
        self.assertEqual(data['usage_meter']['totals']['bob'], {'hysteria': 100})
        self.assertEqual(data['usage_meter']['adjustments']['bob'], {'hysteria': 10})
        self.assertEqual(data['usage_meter']['totals']['alice'], {'hysteria': 999})
        self.assertEqual(data['usage_meter']['adjustments']['alice'], {'hysteria': 77})

    def test_create_rejects_control_chars_in_password(self):
        """网页表单创建用户时，密码包含换行或空字节等控制字符必须被 400 拒绝。"""
        for raw_pwd in ('abc%0ddef', 'abc%0adef', 'abc%00def'):
            data = {'token': 'tok', 'users': {}}
            save_mock = mock.Mock()
            fn = self._build_fn(data, save_mock)
            body = f'action=create&user_id=u1&password={raw_pwd}&duration_days=30'.encode('utf-8')
            code, _ = fn(_FakeHandler(body), '/tok/')
            self.assertEqual(code, 400, f'含控制字符的密码 {raw_pwd} 应返回 400')
            self.assertNotIn('u1', data['users'])
            save_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
