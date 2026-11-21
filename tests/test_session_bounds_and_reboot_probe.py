"""回归测试：verify_session 限制 Cookie 体积与候选数量防哈希放大、拦截非 ASCII 时间戳；sign_session 加锁；reboot-server 校验可执行命令。"""

import hashlib
import hmac
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402
from test_session_cookie_and_github_token_cache import _extract_verify_session  # noqa: E402


class SessionBoundsAndRebootProbeTests(unittest.TestCase):
    def test_verify_session_rejects_oversized_cookie_and_unicode_timestamp(self):
        """超长 Cookie 头（>16KiB）、超过 16 个冗余候选以及全角数字时间戳都应被安全拒绝。"""
        data = {'token': 'tok123', 'session_epoch': 0}
        sign_session, verify_session = _extract_verify_session(data)
        valid = sign_session('tok123')

        # 1) 超长 Cookie 头直接拒绝
        huge_cookie = 'pad=' + ('x' * 17000) + f'; hy2_session={valid}'
        self.assertFalse(verify_session(huge_cookie), '超长 Cookie 头不应参与验签')

        # 2) 前面塞 20 个假候选后才放有效 Cookie：超过 16 候选上限应停止继续做 HMAC
        many_dups = '; '.join([f'hy2_session=tok123.100.sig{i}' for i in range(20)]) + f'; hy2_session={valid}'
        self.assertFalse(verify_session(many_dups), '超过 16 个同名候选不应继续计算 HMAC')

        # 3) 全角数字时间戳不得通过 isdigit() 校验
        now = int(time.time())
        fullwidth_ts = str(now).translate(str.maketrans('0123456789', '０１２３４５６７８９'))
        sig = hmac.new(b'sec_test', f'sess:tok123:{fullwidth_ts}'.encode(), hashlib.sha256).hexdigest()
        self.assertFalse(verify_session(f'hy2_session=tok123.{fullwidth_ts}.{sig}'))

    def test_sign_session_reads_epoch_under_data_lock(self):
        """sign_session 应在 data_lock 内读取 session_epoch。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        s = src.index('    def sign_session(')
        e = src.index('    def verify_session(', s)
        self.assertIn('with data_lock:', src[s:e])

    def test_reboot_server_returns_500_when_no_reboot_command_exists(self):
        """当系统缺少 systemctl 与 reboot 命令时，_h_post_reboot_server 必须返回 500 而不谎报 200。"""
        popen_mock = mock.Mock()
        ns = dict(
            portal.__dict__,
            shutil=SimpleNamespace(which=lambda _: None),
            Path=lambda p: SimpleNamespace(exists=lambda: False),
            subprocess=SimpleNamespace(Popen=popen_mock, DEVNULL=portal.subprocess.DEVNULL),
        )
        fn = extract_method('_h_post_reboot_server', ns)
        replies = []
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            _extend_deadline=lambda *a, **kw: True,
            reply_json=lambda code, payload: replies.append((code, payload)),
        )
        fn(handler, '/tok/')
        self.assertEqual(replies[-1][0], 500, replies)
        self.assertFalse(replies[-1][1]['ok'])
        popen_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
