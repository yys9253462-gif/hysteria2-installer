"""回归测试：verify_session 支持多同名 Cookie 候选且防非字符串 token 崩溃；github_token 权限变更必须使缓存失效。"""

import hashlib
import hmac
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_verify_session(data, session_secret='sec_test'):
    src = (ROOT / 'portal.py').read_text(encoding='utf-8')
    start = src.index('    SESSION_MAX_AGE = ')
    end = src.index('    # SPEEDTEST_TARGETS', start)
    lines = src[start:end].splitlines()
    dedented = '\n'.join(ln[4:] if ln.startswith('    ') else ln for ln in lines)
    ns = {
        'data': data,
        'data_lock': threading.RLock(),
        'session_secret': session_secret,
        'hmac': hmac,
        'hashlib': hashlib,
        'time': time,
    }
    exec(compile(dedented, '<verify_session>', 'exec'), ns)
    return ns['sign_session'], ns['verify_session']


class SessionCookieAndGithubTokenCacheTests(unittest.TestCase):
    def test_verify_session_accepts_valid_cookie_when_stale_duplicate_follows(self):
        """同一 Cookie 头里有效 hy2_session 排在失效同名 Cookie 之前时，仍应认证通过。"""
        data = {'token': 'tok123456', 'session_epoch': 2}
        sign_session, verify_session = _extract_verify_session(data)
        valid = sign_session('tok123456')
        header = f'hy2_session={valid}; hy2_session=tok123456.100.bad_stale_sig'
        self.assertTrue(verify_session(header), '后面的失效同名 Cookie 覆盖了前面的有效会话')

    def test_verify_session_survives_non_string_token_without_type_error(self):
        """data['token'] 被损坏为非字符串时 verify_session 必须安全返回 False，不得抛 TypeError。"""
        data = {'token': 12345, 'session_epoch': 0}
        _, verify_session = _extract_verify_session(data)
        now = int(time.time())
        self.assertFalse(verify_session(f'hy2_session=tok.{now}.deadbeef'))

    def test_github_token_invalidates_cache_when_mode_changes_without_mtime_change(self):
        """token 文件仅权限(st_mode)放宽而 mtime 不变时，缓存必须失效并拒绝读取。"""
        fake_token = 'fake_gh_token_for_test_' + 'A' * 20
        with tempfile.TemporaryDirectory() as td:
            tok_path = Path(td) / 'github-token'
            tok_path.write_text(fake_token, encoding='utf-8')
            real_stat = tok_path.stat()

            class FakeStat:
                def __init__(self, mode, ctime_ns):
                    self.st_mtime = real_stat.st_mtime
                    self.st_mtime_ns = real_stat.st_mtime_ns
                    self.st_ctime_ns = ctime_ns
                    self.st_mode = mode
                    self.st_ino = real_stat.st_ino
                    self.st_size = real_stat.st_size

            stat_seq = [FakeStat(0o100600, 100), FakeStat(0o100644, 200)]

            class FakePath:
                def stat(self):
                    return stat_seq[0]

                def read_text(self, encoding='utf-8'):
                    return tok_path.read_text(encoding=encoding)

                def __str__(self):
                    return str(tok_path)

            fake_p = FakePath()
            with mock.patch.object(portal, 'GITHUB_TOKEN_FILE', fake_p), \
                 mock.patch.object(portal.os, 'name', 'posix'):
                # 重置缓存
                portal._github_token_cache = {'mtime': None, 'stamp': None, 'token': ''}
                first = portal.github_token()
                self.assertEqual(first, fake_token)
                # 仅改变权限位（模拟 chmod 644，mtime 保持不变）
                stat_seq.pop(0)
                second = portal.github_token()
                self.assertEqual(second, '', '权限放宽为 0644 后缓存未失效，仍返回了旧令牌')


if __name__ == '__main__':
    unittest.main()
