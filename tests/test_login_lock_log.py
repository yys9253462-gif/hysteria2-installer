"""Web 登录锁定按来源留痕（2026-11-13 修）。

旧实现全局只记一条「登录失败达上限」、有人登录成功才重置：之后别的来源被锁、同一来源过了
10 分钟再被锁都没有日志，而那唯一一条里也没有来源 —— 本来就是为了分清「自己输错」和「有人在刷」。
"""
import collections
import contextlib
import io
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402

METHODS = ('login_rate_limited', 'record_login_failure', '_web_source_key', 'clear_login_failures')


class LoginLockLogTest(unittest.TestCase):
    def setUp(self):
        ns = dict(portal.__dict__, data_lock=threading.RLock())
        self.methods = {name: extract_method(name, ns) for name in METHODS}
        self.server = SimpleNamespace(login_failures=[], login_source_failures=collections.OrderedDict())
        self.clock = [1000.0]

    def handler(self, ip):
        h = SimpleNamespace(server=self.server, headers={'X-Forwarded-For': ip}, client_address=('127.0.0.1', 1))
        h._web_source_key = lambda: self.methods['_web_source_key'](h)
        return h

    def call(self, name, ip):
        out = io.StringIO()
        with patch.object(portal.time, 'monotonic', lambda: self.clock[0]), contextlib.redirect_stderr(out):
            result = self.methods[name](self.handler(ip))
        return result, out.getvalue()

    def lock_out(self, ip):
        for _ in range(10):
            self.call('record_login_failure', ip)
        return self.call('login_rate_limited', ip)

    def test_each_locked_source_is_logged_once_per_lockout_with_its_address(self):
        locked, log = self.lock_out('198.51.100.20')
        self.assertTrue(locked)
        self.assertIn(portal.auth_rate_key('198.51.100.20'), log)
        self.assertEqual(self.call('login_rate_limited', '198.51.100.20')[1], '', '同一轮锁定重复记日志')
        locked, log = self.lock_out('203.0.113.30')
        self.assertTrue(locked)
        self.assertIn(portal.auth_rate_key('203.0.113.30'), log, '第二个被锁的来源没有留下日志')
        # 过了一轮（10 分钟）同一来源再被锁，要再记一条。
        self.clock[0] += 601
        locked, log = self.lock_out('198.51.100.20')
        self.assertTrue(locked)
        self.assertIn(portal.auth_rate_key('198.51.100.20'), log)


if __name__ == '__main__':
    unittest.main()
