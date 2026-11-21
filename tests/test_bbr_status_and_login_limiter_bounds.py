"""回归测试：_h_get_bbr_status 忽略注释行与行尾注释，以及登录限流器过期条目清理与容量封顶。"""

import collections
import contextlib
import io
import sys
import tempfile
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


class BbrStatusAndLoginLimiterBoundsTests(unittest.TestCase):
    def test_bbr_status_ignores_commented_lines_and_inline_comments(self):
        """99-bbr.conf 里的注释行与行尾注释不得覆盖有效配置并触发虚假 need_reboot。"""
        ns = dict(portal.__dict__, data_lock=threading.RLock(), data={'bbr_target_version': 'v1'})
        fn = extract_method('_h_get_bbr_status', ns)

        with tempfile.TemporaryDirectory() as td:
            conf = Path(td) / '99-bbr.conf'
            conf.write_text(
                '# hy2-managed\n'
                'net.ipv4.tcp_congestion_control = bbr  # 生效值\n'
                '# net.ipv4.tcp_congestion_control = cubic\n'
                '; net.ipv4.tcp_congestion_control = reno\n',
                encoding='utf-8',
            )
            replies = []

            def fake_run(args, **kwargs):
                if args == ['sysctl', '-n', 'net.ipv4.tcp_congestion_control']:
                    return SimpleNamespace(returncode=0, stdout='bbr\n', stderr='')
                if args == ['sysctl', '-n', 'net.core.default_qdisc']:
                    return SimpleNamespace(returncode=0, stdout='fq\n', stderr='')
                if args == ['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']:
                    return SimpleNamespace(returncode=0, stdout='reno cubic bbr\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            real_path = Path

            def fake_path(p):
                if str(p) == '/etc/sysctl.d/99-bbr.conf':
                    return conf
                return real_path(p)

            handler = SimpleNamespace(
                is_authenticated=lambda: True,
                reply_json=lambda code, payload: replies.append((code, payload)),
            )
            ns['Path'] = fake_path
            ns['subprocess'] = SimpleNamespace(run=fake_run)
            ns['sysctl_conf_overrides'] = lambda mapping: None
            ns['_kernel_bbr_modules'] = lambda: []
            fn(handler, '/bbr-status')

        self.assertEqual(len(replies), 1)
        code, payload = replies[0]
        self.assertEqual(code, 200, payload)
        self.assertFalse(payload['need_reboot'], f'注释行误导致虚假 need_reboot: {payload}')

    def test_login_limiter_prunes_stale_entries_and_caps_logged_table(self):
        """过期登录失败记录与空来源桶必须及时清理，且锁定日志去重表有容量上限。"""
        ns = dict(portal.__dict__, data_lock=threading.RLock())
        methods = {
            name: extract_method(name, ns)
            for name in ('login_rate_limited', 'record_login_failure', '_web_source_key')
        }
        server = SimpleNamespace(login_failures=[], login_source_failures=collections.OrderedDict())
        clock = [1000.0]

        def make_handler(ip):
            h = SimpleNamespace(server=server, headers={'X-Forwarded-For': ip}, client_address=('127.0.0.1', 1))
            h._web_source_key = lambda: methods['_web_source_key'](h)
            return h

        with mock.patch.object(portal.time, 'monotonic', lambda: clock[0]):
            # 1) 某来源失败 3 次，过 601 秒后再检查必须清掉该空来源桶
            methods['record_login_failure'](make_handler('198.51.100.1'))
            methods['record_login_failure'](make_handler('198.51.100.1'))
            clock[0] += 601.0
            self.assertFalse(methods['login_rate_limited'](make_handler('198.51.100.1')))
            self.assertEqual(len(server.login_source_failures), 0,
                             f'过期的空来源桶未被删除: {server.login_source_failures}')

            # 2) 仅调用 record_login_failure 跨越窗口时也必须淘汰 600 秒以前的全局旧记录
            clock[0] = 2000.0
            for _ in range(5):
                methods['record_login_failure'](make_handler('198.51.100.2'))
            clock[0] = 2700.0
            methods['record_login_failure'](make_handler('198.51.100.3'))
            self.assertEqual(len(server.login_failures), 1,
                             f'record_login_failure 未清理过期全局记录: {server.login_failures}')

            # 3) _login_lock_logged_at 即使同窗口内被灌入超多键也必须受上限（<=4096）约束
            logged = server.__dict__.setdefault('_login_lock_logged_at', {})
            for idx in range(5000):
                logged[f'src-{idx}'] = clock[0] - 10
            server.login_failures = [clock[0] - 1] * 200
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                self.assertTrue(methods['login_rate_limited'](make_handler('198.51.100.9')))
            self.assertLessEqual(len(server._login_lock_logged_at), 4096,
                                 f'_login_lock_logged_at 超出 4096 上限: {len(server._login_lock_logged_at)}')


if __name__ == '__main__':
    unittest.main()
