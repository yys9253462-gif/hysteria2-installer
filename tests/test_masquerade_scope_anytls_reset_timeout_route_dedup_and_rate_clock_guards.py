"""回归测试：read_masquerade_port 段限定/体积/超长端口、apply_anytls_config reset-failed 超时隔离、规则去重与限流时钟回拨。"""
from __future__ import annotations

import collections
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_handler_rate_methods():
    src = (ROOT / "portal.py").read_text(encoding="utf-8")
    start = src.index("        def check_rate_limit(self, bucket='web'):")
    end = src.index("        def handle_one_request(self):", start)
    lines = src[start:end].splitlines()
    dedented = "\n".join(ln[8:] if ln.startswith("        ") else ln for ln in lines)
    ns = dict(portal.__dict__, data_lock=threading.RLock())
    exec(compile(dedented, "<rate_methods>", "exec"), ns)
    return ns


class MasqueradeAnytlsRouteAndRateGuardTests(unittest.TestCase):
    """验证第五十八批第 1 项的 5 组边界防护。"""

    def test_read_masquerade_port_scopes_to_masquerade_and_guards_huge_digits_and_oversized_file(self):
        """read_masquerade_port 不得跨段误抓 listenHTTPS，且对超长端口数字和 >4MiB 大文件安全返回 None。"""
        with tempfile.TemporaryDirectory(prefix="hy2-masq-") as td:
            p = Path(td) / "config.yaml"
            p.write_text("listen: :443\nother:\n  listenHTTPS: :9999\nmasquerade:\n  type: proxy\n", encoding="utf-8")
            self.assertIsNone(portal.read_masquerade_port(str(p)), "不得抓取 masquerade 段外的 listenHTTPS")

            huge = "9" * 5000
            p.write_text(f"masquerade:\n  listenHTTPS: :{huge}\n", encoding="utf-8")
            self.assertIsNone(portal.read_masquerade_port(str(p)), "超长端口数字不得抛 ValueError")

            big = Path(td) / "big.yaml"
            big.write_bytes(b"masquerade:\n  listenHTTPS: :8443\n" + b"a" * (4 * 1024 * 1024 + 32))
            self.assertIsNone(portal.read_masquerade_port(str(big)), "超过 4 MiB 的配置应拒读返回 None")

    def test_apply_anytls_config_isolates_reset_failed_timeout_and_rejects_nan(self):
        """apply_anytls_config 必须拒绝含 NaN 配置，且正向/回滚 reset-failed 超时不得跳过 restart。"""
        with tempfile.TemporaryDirectory(prefix="hy2-anytls-tx-") as td:
            cfg_path = Path(td) / "anytls.json"
            cfg_path.write_text('{"old": true}', encoding="utf-8")

            # 1) 含 NaN 必须拒绝写入
            with self.assertRaises(ValueError):
                portal.apply_anytls_config({"bad": float("nan")}, cfg_path, restart=False, run=mock.Mock())

            # 2) 正向 reset-failed 超时不应阻碍 restart 与 is-active 成功
            calls = []

            def fake_run_forward(cmd, **kw):
                calls.append(list(cmd))
                if cmd[:2] == ["systemctl", "reset-failed"]:
                    raise subprocess.TimeoutExpired(cmd, 5)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            portal.apply_anytls_config({"inbounds": []}, cfg_path, restart=True, run=fake_run_forward)
            self.assertIn(["systemctl", "restart", portal.ANYTLS_SERVICE], calls)

            # 3) 正向 restart 失败触发回滚时，回滚 reset-failed 超时也不得跳过回滚 restart
            rb_calls = []
            restart_seen = [0]

            def fake_run_rollback(cmd, **kw):
                rb_calls.append(list(cmd))
                if cmd[:2] == ["systemctl", "reset-failed"]:
                    raise subprocess.TimeoutExpired(cmd, 5)
                if cmd[:2] == ["systemctl", "restart"]:
                    restart_seen[0] += 1
                    if restart_seen[0] == 1:
                        raise subprocess.CalledProcessError(1, cmd)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with self.assertRaises(subprocess.CalledProcessError):
                portal.apply_anytls_config({"inbounds": ["new"]}, cfg_path, restart=True, run=fake_run_rollback)
            self.assertEqual(restart_seen[0], 2, f"回滚阶段 reset-failed 超时不得跳过回滚 restart，实际调用={rb_calls}")

    def test_normalize_route_rules_deduplicates_and_render_egress_rejects_non_str(self):
        """normalize_route_rules 应保序去重；render_egress_config 拒绝非字符串原始配置。"""
        rules = [
            {"domain": "example.com", "outbound": "warp_socks"},
            {"domain": "EXAMPLE.COM.", "outbound": "warp_socks"},
            {"domain": "example.com", "outbound": "proxy1"},
            {"domain": "openai.com", "outbound": "warp_socks"},
            {"domain": "openai.com", "outbound": "warp_socks"},
        ]
        norm = portal.normalize_route_rules(rules)
        self.assertEqual(
            norm,
            [
                {"domain": "example.com", "outbound": "warp_socks"},
                {"domain": "example.com", "outbound": "proxy1"},
                {"domain": "openai.com", "outbound": "warp_socks"},
            ],
        )
        with self.assertRaises(ValueError):
            portal.render_egress_config(None, {})

    def test_rate_limit_prunes_future_timestamps_on_clock_rollback_and_caps_login_failures(self):
        """时钟回拨时未来时间戳不得永久占位；record_login_failure 必须有长度上限，且缺 headers 不崩溃。"""
        ns = _extract_handler_rate_methods()
        server = SimpleNamespace(
            api_requests=[1000.0] * 50,
            api_anon_requests=[],
            auth_requests=[],
            requests=[],
            login_failures=[1000.0] * 250,
            login_source_failures=collections.OrderedDict({"1.2.3.4": [1000.0] * 12}),
            web_failure_limiter=portal.AuthLimiter(),
        )
        handler = SimpleNamespace(
            server=server,
            headers=None,
            client_address=("1.2.3.4", 12345),
        )
        for name in ("check_rate_limit", "login_rate_limited", "record_login_failure", "_web_source_key"):
            setattr(handler, name, ns[name].__get__(handler))

        # 模拟单调时钟回拨到 500.0（小于记录里的 1000.0）
        with mock.patch.object(portal.time, "monotonic", return_value=500.0):
            self.assertEqual(handler._web_source_key(), "1.2.3.4")
            self.assertTrue(handler.check_rate_limit("api"), "时钟回拨时未来时间戳应被清理而非永久阻塞")
            self.assertFalse(handler.login_rate_limited(), "时钟回拨时未来登录失败时间戳应被清理而非永久锁定")

        # 模拟突发海量失败：列表长度必须有界
        server.login_failures = [500.0] * 2000
        with mock.patch.object(portal.time, "monotonic", return_value=501.0):
            handler.record_login_failure()
        self.assertLessEqual(len(server.login_failures), 1000)

    def test_singbox_version_rejects_unsafe_binary_and_overlong_numbers(self):
        """_singbox_version 拒连字符/控制字符 binary 与超长版本号数字。"""
        run_mock = mock.Mock(return_value=SimpleNamespace(stdout="sing-box version 1.12.0"))
        self.assertIsNone(portal._singbox_version("-bad-bin", run=run_mock))
        self.assertIsNone(portal._singbox_version("/usr/bin/sb\n", run=run_mock))
        run_mock.assert_not_called()

        huge_out = SimpleNamespace(stdout="sing-box version 1." + ("9" * 5000) + ".0")
        self.assertIsNone(portal._singbox_version("/usr/bin/sing-box", run=mock.Mock(return_value=huge_out)))


if __name__ == "__main__":
    unittest.main()
