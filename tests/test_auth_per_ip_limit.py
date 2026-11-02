"""H4（2026-11-02）：/auth 失败桶与速率桶按客户端地址分桶，不能让一个来源锁死全节点。"""
import ast
import copy
import io
import json
import re
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SOURCE = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _handler_methods():
    """从 serve() 里的 Handler 类取出 auth_rate_limited / record_auth_failure 原文。"""
    cls = next(n for n in ast.walk(TREE) if isinstance(n, ast.ClassDef) and n.name == 'Handler')
    return [copy.deepcopy(n) for n in cls.body if isinstance(n, ast.FunctionDef)
            and n.name in ('auth_rate_limited', 'record_auth_failure')]


class AuthEndToEndHarness:
    """把真实 /auth 分支 + 真实限流方法拼成一个可调用的处理器（不起服务）。"""

    def __init__(self, users):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "self.path == '/auth'")
        fn = ast.parse('def handle(self):\n    pass').body[0]
        fn.body = [copy.deepcopy(branch)]
        cls = ast.ClassDef(name='H', bases=[], keywords=[], decorator_list=[],
                           body=_handler_methods() + [fn])
        self.env = dict(portal.__dict__, data={'users': users}, data_lock=threading.RLock(),
                        ip_tracker={}, global_ip_deny={}, live_online_ips=lambda uid: set(),
                        reality_live_ips=lambda uid: set())
        exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])),
                     '<auth-per-ip>', 'exec'), self.env)
        self.server = SimpleNamespace(auth_limiter=portal.AuthLimiter())

    def auth(self, password, addr):
        body = json.dumps({'auth': password, 'addr': addr}).encode()
        h = self.env['H']()
        h.path = '/auth'
        h.client_address = ('127.0.0.1', 1234)
        h.headers = {'Content-Length': str(len(body))}
        h.rfile = io.BytesIO(body)
        h.server = self.server
        h.reply_json = lambda status, payload: payload
        return h.handle()


class PerIpAuthLimitTest(unittest.TestCase):
    def setUp(self):
        self.h = AuthEndToEndHarness({'u1': {'password': 'goodpw', 'status': 'active'}})
        self.clock = [1000.0]
        p = patch.object(time, 'monotonic', side_effect=lambda: self.clock[0])
        p.start()
        self.addCleanup(p.stop)

    def burn(self, addr, n=35):
        # 每次间隔 0.1s：速率桶（1 秒 20 次）不触发，只测失败桶
        for i in range(n):
            self.clock[0] += 0.1
            self.h.auth('wrong-%d' % i, addr)

    def test_one_ip_failures_do_not_lock_out_other_ips(self):
        self.burn('198.51.100.7:4433')
        self.clock[0] += 0.1
        self.assertEqual(self.h.auth('goodpw', '198.51.100.7:4433')['msg'], 'Auth service busy',
                         '攻击来源本身应被限')
        self.clock[0] += 0.1
        ok = self.h.auth('goodpw', '203.0.113.20:5555')
        self.assertTrue(ok['ok'], '另一来源的合法用户被连坐拒绝：%r' % ok)

    def test_ipv6_and_bracket_forms_share_a_bucket(self):
        self.burn('[2001:db8::1]:443', 15)
        self.burn('[2001:db8:0:0::2]:443', 20)  # 同一 /64
        self.clock[0] += 0.1
        self.assertEqual(self.h.auth('goodpw', '[2001:db8::3]:1')['msg'], 'Auth service busy')
        self.clock[0] += 0.1
        self.assertTrue(self.h.auth('goodpw', '[2001:db8:1::1]:1')['ok'])

    def test_failure_window_expires(self):
        self.burn('198.51.100.7:1')
        self.clock[0] += 61
        self.assertTrue(self.h.auth('goodpw', '198.51.100.7:1')['ok'])

    def test_per_ip_rate_limit(self):
        # 时钟不动 = 同一秒内：前 20 次放行，之后被速率桶拒；别的来源不受影响
        first = [self.h.auth('goodpw', '198.51.100.9:1') for _ in range(20)]
        self.assertTrue(all(r['ok'] for r in first))
        res = [self.h.auth('goodpw', '198.51.100.9:1') for _ in range(5)]
        self.assertTrue(all(r.get('msg') == 'Auth service busy' for r in res))
        self.assertTrue(self.h.auth('goodpw', '198.51.100.10:1')['ok'])

    def test_global_backstop_still_applies(self):
        # 500 个不同来源同一秒内各一次 → 第 501 次（新来源）被全局兜底拒
        for i in range(500):
            self.h.auth('goodpw', '10.%d.%d.1:1' % (i // 250, i % 250))
        self.assertEqual(self.h.auth('goodpw', '192.0.2.1:1')['msg'], 'Auth service busy')
        self.clock[0] += 1.1
        self.assertTrue(self.h.auth('goodpw', '192.0.2.1:1')['ok'])


class AuthLimiterBoundsTest(unittest.TestCase):
    def test_bucket_count_is_bounded_and_evicts_oldest(self):
        lim = portal.AuthLimiter(max_buckets=100)
        for i in range(250):
            lim.record_failure('ip-%d' % i, 1.0)
        self.assertEqual(len(lim.buckets), 100)
        self.assertNotIn('ip-0', lim.buckets)
        self.assertIn('ip-249', lim.buckets)

    def test_rate_key(self):
        self.assertEqual(portal.auth_rate_key('198.51.100.7'), '198.51.100.7')
        self.assertEqual(portal.auth_rate_key('::ffff:198.51.100.7'), '198.51.100.7')
        self.assertEqual(portal.auth_rate_key('2001:db8::5'), '2001:db8::/64')
        self.assertEqual(portal.auth_rate_key(''), '')


class ListenBacklogTest(unittest.TestCase):
    def test_request_queue_size_is_128(self):
        cls = next(n for n in ast.walk(TREE) if isinstance(n, ast.ClassDef)
                   and n.name == 'ThreadingHTTPServer')
        values = {t.id: ast.literal_eval(n.value) for n in cls.body if isinstance(n, ast.Assign)
                  for t in n.targets if isinstance(t, ast.Name)}
        self.assertEqual(values.get('request_queue_size'), 128)


class LogLevelDropinTest(unittest.TestCase):
    def test_install_writes_error_level_dropin(self):
        install = (ROOT / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('HY2_LOG_LEVEL="${HY2_LOG_LEVEL:-error}"', install)
        self.assertIn('hysteria-server.service.d/loglevel.conf', install)
        self.assertRegex(install, re.compile(r'Environment=HYSTERIA_LOG_LEVEL=\$\{HY2_LOG_LEVEL\}'))


if __name__ == '__main__':
    unittest.main()
