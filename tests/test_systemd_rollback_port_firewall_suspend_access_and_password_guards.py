"""回归测试：portal.py 服务回滚、端口与防火墙校验、流量停用补偿、凭据恢复与密码冲突检查。"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_set_traffic_suspension(ns):
    src = (ROOT / "portal.py").read_text(encoding="utf-8")
    start = src.index("    def _set_traffic_suspension(suspend):")
    end = src.index("    # 计量每 5 秒对每个来源采样一次", start)
    lines = src[start:end].splitlines()
    dedented = "\n".join(ln[4:] if ln.startswith("    ") else ln for ln in lines)
    exec(compile(dedented, "<_set_traffic_suspension>", "exec"), ns)
    return ns["_set_traffic_suspension"]


class SystemdPortSuspendAccessAndPasswordGuardTests(unittest.TestCase):
    """验证 5 组核心服务/端口/停用/凭据/密码安全边界。"""

    def test_restore_systemd_service_state_isolates_reset_failed_timeout_and_allows_failed_inactive(self):
        """reset-failed 超时不得跳过 restart；原状态为 failed 时回滚后保持 failed 也应判成功；非字典快照返回 False。"""
        self.assertFalse(portal._restore_systemd_service_state("hy2-anytls", None))
        self.assertFalse(portal._restore_systemd_service_state("-bad-unit", {"active": "active", "enabled": "enabled"}))

        calls = []

        def fake_run_timeout(cmd, **kw):
            calls.append(list(cmd))
            if cmd[:2] == ["systemctl", "reset-failed"]:
                raise subprocess.TimeoutExpired(cmd, 15)
            if cmd[:2] == ["systemctl", "is-active"]:
                return SimpleNamespace(returncode=0, stdout="active\n")
            if cmd[:2] == ["systemctl", "is-enabled"]:
                return SimpleNamespace(returncode=0, stdout="enabled\n")
            return SimpleNamespace(returncode=0, stdout="")

        with mock.patch.object(portal.subprocess, "run", side_effect=fake_run_timeout):
            ok = portal._restore_systemd_service_state("hy2-anytls", {"active": "active", "enabled": "enabled"})
        self.assertTrue(ok, "reset-failed 超时不应阻止 restart 恢复服务")
        self.assertIn(["systemctl", "restart", "hy2-anytls"], calls)

        def fake_run_failed(cmd, **kw):
            if cmd[:2] == ["systemctl", "is-active"]:
                return SimpleNamespace(returncode=3, stdout="failed\n")
            if cmd[:2] == ["systemctl", "is-enabled"]:
                return SimpleNamespace(returncode=1, stdout="disabled\n")
            return SimpleNamespace(returncode=0, stdout="")

        with mock.patch.object(portal.subprocess, "run", side_effect=fake_run_failed):
            ok_failed = portal._restore_systemd_service_state("hy2-tuic", {"active": "failed", "enabled": "disabled"})
        self.assertTrue(ok_failed, "原状态为 failed 且 stop 后仍为 failed 应视为回滚成功")

    def test_protocol_port_in_use_and_firewall_port_reject_zero_inf_float_and_leading_zero(self):
        """protocol_port_in_use 与 firewall_port 必须拒绝 0、Inf/NaN、小数与前导零，并不因脏配置抛出 OverflowError。"""
        dirty_data = {
            "reality_config": {"enabled": True, "port": float("inf")},
            "vmess_config": {"enabled": True, "port": None},
            "proxy_services": [{"port": float("nan")}, {"port": "08080"}, {"port": 443}],
        }
        dirty_xray = {"inbounds": [{"tag": portal.REALITY_INBOUND_TAG, "port": float("inf")}]}

        with mock.patch.object(portal, "_systemd_state", return_value="inactive"):
            self.assertFalse(portal.protocol_port_in_use(0, "tcp", dirty_data, dirty_xray))
            self.assertFalse(portal.protocol_port_in_use(float("inf"), "tcp", dirty_data, dirty_xray))
            self.assertFalse(portal.protocol_port_in_use(443.5, "tcp", dirty_data, dirty_xray))
            self.assertFalse(portal.protocol_port_in_use("0443", "tcp", dirty_data, dirty_xray))
            self.assertTrue(portal.protocol_port_in_use(443, "tcp", dirty_data, dirty_xray))

        self.assertFalse(portal.firewall_port(float("inf"), "tcp", True))
        self.assertFalse(portal.firewall_port(443.9, "tcp", True))
        self.assertFalse(portal.firewall_port("0443", "tcp", True))

    def test_suspend_state_dedups_and_sanitizes_since_and_reentrant_save_fail_does_not_start_already_stopped(self):
        """suspend_state 去重并清洗非有限 since；已停用重入遇保存失败，补偿绝不得拉起原本已停用的服务。"""
        cleaned = portal.suspend_state({
            "traffic_suspend": {
                "suspended": True,
                "units": ["hysteria-server", "xray", "hysteria-server"],
                "since": float("nan"),
            }
        })
        self.assertEqual(cleaned["units"], ["hysteria-server", "xray"])
        self.assertNotIn("since", cleaned)

        calls = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        # 已停用状态：hysteria-server 早已停用（inactive），xray 停用期间被人手动拉起（active）
        data = {
            "traffic_suspend": {
                "suspended": True,
                "units": ["hysteria-server"],
                "since": 1700000000,
            }
        }
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            TRAFFIC_SUSPEND_UNITS=("hysteria-server", "xray"),
            ANYTLS_SERVICE=portal.ANYTLS_SERVICE,
            TUIC_SERVICE=portal.TUIC_SERVICE,
            _unit_active=lambda u: u == "xray",
            save_data=mock.Mock(side_effect=OSError("disk full")),
            subprocess=SimpleNamespace(
                run=fake_run,
                TimeoutExpired=subprocess.TimeoutExpired,
                SubprocessError=subprocess.SubprocessError,
            ),
            copy=copy,
            time=time,
        )
        fn = _extract_set_traffic_suspension(ns)
        with self.assertRaises(OSError):
            fn(True)

        self.assertIn(["systemctl", "start", "xray"], calls, "原本在运行的 xray 应被补偿拉起")
        self.assertNotIn(
            ["systemctl", "start", "hysteria-server"],
            calls,
            "原本早已停用的 hysteria-server 绝不得在补偿分支被错误拉起",
        )

    def test_ensure_portal_access_rebuilds_corrupt_credentials_and_sanitizes_non_str_token(self):
        """portal-access.json 用户名含冒号或控制字符时必须重建；非字符串 token 不得拼出 /None/。"""
        with tempfile.TemporaryDirectory(prefix="hy2-access-guard-") as td:
            root = Path(td)
            (root / "portal-access.json").write_text(
                json.dumps({"username": "bad:user\n", "password": "ok"}),
                encoding="utf-8",
            )
            meta = {"domain": "example.com", "subscription_port": 8443}
            data = {"token": None, "api_key": 12345}
            access, rebuilt = portal.ensure_portal_access(root, meta, data)
            self.assertTrue(rebuilt, "含冒号与换行的用户名必须判定损坏并重建")
            self.assertNotIn(":", access["username"])
            self.assertNotIn("/None/", access["url"])
            self.assertEqual(access["api_key"], "")

    def test_password_taken_ignores_none_and_empty_and_non_str_user_passwords(self):
        """password_taken 对空密码、None 或缺失 password 字段的用户绝不得误判冲突。"""
        users = {
            "master": {"password": "None"},
            "u1": {"note": "missing password"},
            "u2": {"password": ""},
            "u3": {"password": "real-secret"},
        }
        self.assertFalse(portal.password_taken(users, None, "u9"))
        self.assertFalse(portal.password_taken(users, "", "u9"))
        self.assertFalse(portal.password_taken(users, 123, "u9"))
        self.assertTrue(portal.password_taken(users, "real-secret", "u9"))
        self.assertFalse(portal.password_taken(users, "real-secret", "u3"))


if __name__ == "__main__":
    unittest.main()
