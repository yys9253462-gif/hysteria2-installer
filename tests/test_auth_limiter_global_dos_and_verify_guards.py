"""回归测试：AuthLimiter 已拉黑来源不消耗全局配额防 DoS 放大；verify_api_key 与 is_authenticated 容忍坏/非 ASCII 配置并加锁读取。"""

import hashlib
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class AuthLimiterGlobalDosAndVerifyGuardsTests(unittest.TestCase):
    def test_blocked_attacker_does_not_exhaust_global_rate_for_legit_users(self):
        """已因失败超限被封禁的来源继续刷请求时，不得占用 global_requests 拖死合法用户。"""
        limiter = portal.AuthLimiter(per_ip_rate=20, per_ip_failures=2, failure_window=60, global_rate=5)
        now = 1000.0
        # 攻击者连续 2 次失败进入封禁状态
        limiter.record_failure('198.51.100.9', now)
        limiter.record_failure('198.51.100.9', now)
        # 被封后继续狂发 10 次请求
        for _ in range(10):
            self.assertTrue(limiter.limited('198.51.100.9', now + 0.1))
        # 此时全局配额应为 0，合法用户首次连接必须放行
        self.assertFalse(
            limiter.limited('203.0.113.5', now + 0.1),
            '被失败封禁的攻击者耗尽了全局限流配额，导致合法用户被误拒',
        )

    def test_verify_api_key_handles_non_ascii_stored_key_under_lock(self):
        """portal.json 的 api_key 被写坏成含非 ASCII 字符时 verify_api_key 必须返回 False 而不抛 TypeError。"""
        ns = dict(
            portal.__dict__,
            data={'api_key': '中文坏密钥'},
            data_lock=threading.RLock(),
        )
        fn = extract_method('verify_api_key', ns)
        handler = SimpleNamespace(headers={'Authorization': 'Bearer abc'})
        self.assertFalse(fn(handler))

        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        s = src.index('        def verify_api_key(self):')
        e = src.index('        def is_authenticated(self):', s)
        self.assertIn('with data_lock:', src[s:e])

    def test_is_authenticated_survives_missing_or_corrupt_auth_hash_under_lock(self):
        """auth_hash 缺失、非字符串或含非 ASCII 时 is_authenticated 不得抛 KeyError/TypeError。"""
        for bad_data in ({}, {'auth_hash': None}, {'auth_hash': 123}, {'auth_hash': '非ASCII哈希'}):
            with self.subTest(bad_data=bad_data):
                ns = dict(
                    portal.__dict__,
                    data=dict(bad_data),
                    data_lock=threading.RLock(),
                    verify_session=lambda _: False,
                )
                fn = extract_method('is_authenticated', ns)
                handler = SimpleNamespace(headers={'Authorization': 'Basic dXNlcjpwYXNz', 'Cookie': ''})
                self.assertFalse(fn(handler))

        # 正常 auth_hash 仍正确通过
        good_hash = hashlib.sha256(b'dXNlcjpwYXNz').hexdigest()
        ns_ok = dict(
            portal.__dict__,
            data={'auth_hash': good_hash},
            data_lock=threading.RLock(),
            verify_session=lambda _: False,
        )
        fn_ok = extract_method('is_authenticated', ns_ok)
        self.assertTrue(fn_ok(SimpleNamespace(headers={'Authorization': 'Basic dXNlcjpwYXNz', 'Cookie': ''})))


if __name__ == '__main__':
    unittest.main()
