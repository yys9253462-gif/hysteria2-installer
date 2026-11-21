"""回归测试：流媒体解锁总超时上限与 HTTPError 连接关闭，以及 cert_status 损坏自愈状态防护。"""

import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class UnlockAndCertStatusGuardsTests(unittest.TestCase):
    def test_run_unlock_checks_uses_shared_deadline_not_serial_per_thread_wait(self):
        """多个探测线程同时卡住时，run_unlock_checks 必须共享单轮总超时而非逐线程串行叠加。"""
        gate = threading.Event()
        sleep_calls = []

        def stuck():
            gate.wait(5)
            return 'yes', 'US', ''

        fake_checks = [(f'k{i}', f'N{i}', stuck) for i in range(4)]
        join_timeouts = []
        orig_join = threading.Thread.join

        def recording_join(self_thread, timeout=None):
            join_timeouts.append(timeout)
            return orig_join(self_thread, 0.01)

        with mock.patch.object(portal, 'UNLOCK_CHECKS', fake_checks), \
             mock.patch.object(threading.Thread, 'join', recording_join):
            # 构造严格递增的单调时钟：每调用一次前进 10 秒，验证剩余时间递减并在超限时归零
            ticks = iter([100.0, 100.0, 110.0, 125.0, 135.0, 145.0, 155.0])
            with mock.patch.object(portal.time, 'monotonic', side_effect=lambda: next(ticks, 200.0)):
                results = portal.run_unlock_checks()
        gate.set()

        self.assertEqual(len(results), 4)
        self.assertTrue(all(r['status'] == 'unknown' for r in results))
        # 若仍是旧的 t.join(30)，四个超时全都是 30；共享总截止时间后必须严格递减且不超 30
        self.assertNotEqual(join_timeouts, [30, 30, 30, 30], f'仍为逐线程固定 30 秒串行等待: {join_timeouts}')
        self.assertLessEqual(max(join_timeouts), 30.0)
        self.assertEqual(join_timeouts[-1], 0.0, f'超时后剩余等待应归零: {join_timeouts}')

    def test_unlock_fetch_closes_http_error_response(self):
        """HTTP 错误响应在读取正文后必须关闭底层连接对象，不得泄漏描述符。"""
        closed = []

        class FakeHTTPError(urllib.error.HTTPError):
            def __init__(self):
                super().__init__('https://example.test/', 403, 'Forbidden', {}, None)

            def read(self, limit=-1):
                return b'forbidden body'

            def close(self):
                closed.append(True)

        err = FakeHTTPError()
        with mock.patch.object(portal.urllib.request, 'urlopen', side_effect=err):
            code, final_url, body = portal._unlock_fetch('https://example.test/')

        self.assertEqual(code, 403)
        self.assertEqual(final_url, 'https://example.test/')
        self.assertEqual(body, 'forbidden body')
        self.assertEqual(closed, [True], 'HTTPError 句柄未被关闭')

    def test_unlock_read_handles_incomplete_read_with_none_partial(self):
        """IncompleteRead.partial 为 None 时不得抛 AttributeError。"""
        class BrokenResp:
            def read(self, limit):
                raise http.client.IncompleteRead(None)

        self.assertEqual(portal._unlock_read(BrokenResp(), 1024), '')

    def test_cert_status_ignores_non_dict_selfheal_state_silently(self):
        """selfheal 状态文件为 JSON 数组/空值时，cert_status 必须平稳跳过且不记录异常。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert_file = root / 'cert.pem'
            cert_file.write_text('dummy', encoding='utf-8')
            heal_file = root / 'cert-heal-state.json'
            heal_file.write_text(json.dumps(['not', 'a', 'dict']), encoding='utf-8')

            logged = []
            fake_proc = mock.Mock(
                returncode=0,
                stdout='issuer=CN=Test CA\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\n',
            )
            with mock.patch.object(portal, '_resolve_live_cert', return_value=(cert_file, 'example.com', ['example.com'], False)), \
                 mock.patch.object(portal.subprocess, 'run', return_value=fake_proc), \
                 mock.patch.object(portal, '_log_ignored', side_effect=lambda tag, exc: logged.append((tag, exc))):
                info = portal.cert_status(root, meta={'server_name': 'example.com'}, selfheal_state_path=heal_file)

            self.assertTrue(info['ok'])
            self.assertEqual(info['heal_count'], 0)
            self.assertFalse(any(tag == 'cert_info.heal_state' for tag, _ in logged),
                             f'非对象 selfheal 状态触发了未拦截异常: {logged}')


if __name__ == '__main__':
    unittest.main()
