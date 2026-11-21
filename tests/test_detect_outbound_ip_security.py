"""回归测试：detect_outbound_ip 禁止将代理账号密码暴露在 curl 命令行，并拦截非法控制字符。"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class DetectOutboundIpSecurityTests(unittest.TestCase):
    def test_proxy_credentials_are_passed_via_stdin_config_not_argv(self):
        """带账号密码的代理探测绝不能把明文凭据放进 curl argv（避免 ps/proc 泄露）。"""
        captured = {}

        def fake_run(args, **kwargs):
            captured['args'] = list(args)
            captured['kwargs'] = dict(kwargs)
            return SimpleNamespace(returncode=0, stdout='{"ip":"198.51.100.88"}', stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ip = portal.detect_outbound_ip('socks5', 'alice:SuperSecretPass@198.51.100.1:1080', timeout=5)

        self.assertEqual(ip, '198.51.100.88')
        argv_joined = ' '.join(captured['args'])
        self.assertNotIn('SuperSecretPass', argv_joined, f'代理明文密码泄漏到命令行参数: {captured["args"]}')
        self.assertNotIn('alice', argv_joined, f'代理用户名泄漏到命令行参数: {captured["args"]}')
        self.assertIn('--config', captured['args'])
        stdin_text = captured['kwargs'].get('input') or ''
        self.assertIn('proxy = "socks5h://alice:SuperSecretPass@198.51.100.1:1080"', stdin_text)

    def test_http_proxy_with_credentials_also_uses_stdin_config(self):
        """带凭据的 HTTP 代理同样通过 stdin 传入 curl 配置。"""
        captured = {}

        def fake_run(args, **kwargs):
            captured['args'] = list(args)
            captured['kwargs'] = dict(kwargs)
            return SimpleNamespace(returncode=0, stdout='{"ip":"203.0.113.9"}', stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ip = portal.detect_outbound_ip('http', 'http://u:p@127.0.0.1:8080', timeout=5)

        self.assertEqual(ip, '203.0.113.9')
        self.assertNotIn('u:p@', ' '.join(captured['args']))
        self.assertIn('proxy = "http://u:p@127.0.0.1:8080"', captured['kwargs'].get('input') or '')

    def test_rejects_proxy_addr_with_control_chars_or_whitespace(self):
        """含换行、控制字符或空白的畸形代理地址必须被直接拦截，不调用 curl。"""
        for bad in ('127.0.0.1:1080\nurl = "file:///etc/passwd"', '127.0.0.1:1080 -o /tmp/x', '127.0.0.1:1080\r\n'):
            with self.subTest(bad=bad):
                with mock.patch.object(portal.subprocess, 'run') as run_mock:
                    self.assertEqual(portal.detect_outbound_ip('socks5', bad), '')
                    run_mock.assert_not_called()

    def test_direct_auto_mode_omits_empty_proxy_flag(self):
        """直连模式无需传空的 --proxy ''，仅传 --noproxy '*'。"""
        captured = {}

        def fake_run(args, **kwargs):
            captured['args'] = list(args)
            return SimpleNamespace(returncode=0, stdout='{"ip":"203.0.113.7"}', stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            self.assertEqual(portal.detect_outbound_ip('auto'), '203.0.113.7')

        self.assertNotIn('--proxy', captured['args'])
        self.assertEqual(captured['args'][captured['args'].index('--noproxy') + 1], '*')


if __name__ == '__main__':
    unittest.main()
