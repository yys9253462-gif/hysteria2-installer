"""回归测试：_h_post_login 遇到损坏非字符串 auth_hash 不得 500，拒绝负长度，且 302 带安全响应头与 Connection: close。"""

import base64
import hashlib
import io
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


class _FakeLoginHandler:
    def __init__(self, body: bytes, content_length=None):
        self.headers = {'Content-Length': str(len(body) if content_length is None else content_length)}
        self.rfile = io.BytesIO(body)
        self.reply_result = None
        self.sent_status = None
        self.sent_headers = []
        self._responded = False
        self.failures = 0
        self.cleared = 0

    def login_rate_limited(self):
        return False

    def record_login_failure(self):
        self.failures += 1

    def clear_login_failures(self):
        self.cleared += 1

    def _is_https_request(self):
        return True

    def reply(self, code, body, mime='text/plain; charset=utf-8', **kw):
        self.reply_result = (code, body)
        return code, body

    def send_response(self, code):
        self.sent_status = code

    def send_header(self, k, v):
        self.sent_headers.append((k, v))

    def end_headers(self):
        pass


class LoginCorruptHashAndHeadersTests(unittest.TestCase):
    def _build_fn(self, data):
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            SESSION_MAX_AGE=30 * 86400,
            sign_session=lambda tok: f'{tok}.123.sig',
        )
        return extract_method('_h_post_login', ns)

    def test_corrupt_non_string_auth_hash_fails_cleanly_without_type_error(self):
        """data['auth_hash'] 被改坏为整数或 None 时，登录应优雅返回失败页而不抛 TypeError。"""
        data = {'token': 'tok123', 'auth_hash': 99999}
        fn = self._build_fn(data)
        h = _FakeLoginHandler(b'username=admin&password=wrong')
        code, _ = fn(h, '/tok123/')
        self.assertEqual(code, 200)
        self.assertEqual(h.failures, 1)

    def test_negative_content_length_returns_400(self):
        """负数 Content-Length 必须直接返回 400，不得传入 rfile.read(-1)。"""
        data = {'token': 'tok123', 'auth_hash': 'a' * 64}
        fn = self._build_fn(data)
        h = _FakeLoginHandler(b'', content_length=-5)
        code, _ = fn(h, '/tok123/')
        self.assertEqual(code, 400)

    def test_login_redirect_sets_connection_close_and_security_headers(self):
        """登录成功 302 跳转必须带 Connection: close 与安全响应头。"""
        good_hash = hashlib.sha256(base64.b64encode(b'admin:pass123')).hexdigest()
        data = {'token': 'tok123', 'auth_hash': good_hash}
        fn = self._build_fn(data)
        h = _FakeLoginHandler(b'username=admin&password=pass123&remember=1')
        fn(h, '/tok123/')
        self.assertEqual(h.sent_status, 302)
        hdrs = {k.lower(): v for k, v in h.sent_headers}
        self.assertEqual(hdrs.get('connection'), 'close')
        self.assertEqual(hdrs.get('x-content-type-options'), 'nosniff')
        self.assertEqual(hdrs.get('x-frame-options'), 'DENY')
        self.assertEqual(hdrs.get('referrer-policy'), 'no-referrer')


if __name__ == '__main__':
    unittest.main()
