"""回归测试：版本号解析超长/全角数字、单元文件损坏编码容错、四协议直链控制字符清洗与 user_access_denial 小数配额/非法 now。"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_gost_helpers(ns):
    src = (ROOT / "portal.py").read_text(encoding="utf-8")
    start = src.index("    def gost_owned():")
    end = src.index("    # ------------------------------------------------------------------\n    # AmneziaWG", start)
    lines = src[start:end].splitlines()
    dedented = "\n".join(ln[4:] if ln.startswith("    ") else ln for ln in lines)
    exec(compile(dedented, "<gost_helpers>", "exec"), ns)
    return ns["gost_owned"], ns["ensure_gost_unit"]


class VersionUnitUriAndAccessDenialGuardTests(unittest.TestCase):
    """验证第五十八批第 2 项的 5 组边界防护。"""

    def test_version_parsers_reject_huge_digits_fullwidth_and_unsafe_xray_binary(self):
        """core_version_key/_version_tuple 拒超长数字与全角数字；_xray_version 拒连字符/控制字符 binary。"""
        huge = "9" * 5000
        self.assertEqual(portal.core_version_key(f"1.{huge}.0"), ())
        self.assertEqual(portal.core_version_key("２.６.７"), ())
        self.assertEqual(portal.core_version_key(12345), ())
        self.assertEqual(portal.core_version_key("v2.6.7"), (2, 6, 7))

        self.assertEqual(portal._version_tuple(f"1.{huge}.0"), ())
        self.assertEqual(portal._version_tuple("２６.３.２７"), ())
        self.assertEqual(portal._version_tuple(True), ())
        self.assertEqual(portal._version_tuple("v26.3.27"), (26, 3, 27))

        run_mock = mock.Mock(return_value=SimpleNamespace(stdout="Xray 26.3.27", stderr=""))
        self.assertEqual(portal._xray_version("-bad-xray", run=run_mock), "")
        self.assertEqual(portal._xray_version("/usr/local/bin/xray\n", run=run_mock), "")
        run_mock.assert_not_called()

    def test_unit_checks_tolerate_non_utf8_corrupt_unit_files(self):
        """xray_unit_foreign 与 gost_owned 遇到非 UTF-8 损坏单元文件时必须走 fail-closed 而非抛 UnicodeDecodeError。"""
        with tempfile.TemporaryDirectory(prefix="hy2-bad-unit-") as td:
            bad_xray = Path(td) / "xray.service"
            bad_xray.write_bytes(b"\xff\xfe\x00invalid-utf8")
            self.assertTrue(portal.xray_unit_foreign(str(bad_xray)), "损坏的 xray.service 应保守判为外源拒绝覆写")

            owned_flag = Path(td) / ".hy2-gost-owned"
            owned_flag.write_text("1", encoding="utf-8")
            bad_gost = Path(td) / "gost.service"
            bad_gost.write_bytes(b"\xff\xfe\x00invalid-utf8")

            orig_path = Path

            def fake_path(p):
                if str(p) == "/etc/systemd/system/gost.service":
                    return bad_gost
                if str(p) == "/etc/hysteria/.hy2-gost-owned":
                    return owned_flag
                return orig_path(p)

            ns = dict(
                portal.__dict__,
                Path=fake_path,
                GOST_SELFCHECK_PATH=Path(td) / "selfcheck.sh",
                GOST_UNIT_CONTENT="ExecStart=/usr/local/bin/gost",
                write_gost_selfcheck=mock.Mock(return_value=False),
            )
            gost_owned, _ensure = _extract_gost_helpers(ns)
            self.assertFalse(gost_owned(), "损坏的 gost.service 应保守返回 False 而不抛 UnicodeDecodeError")

    def test_protocol_uris_reject_invalid_user_id_and_strip_control_chars_from_label_and_secret(self):
        """VMess/AnyTLS/TUIC/VLESS-Enc 直链须拒空或非字符串 user_id、剥离标签控制字符并拦截脏 secret。"""
        vcfg = {"domain": "node.example.com", "port": 8443, "ws_path": "/ws"}
        self.assertEqual(portal.vmess_uri_for_user(vcfg, "", "1.2.3.4"), "")
        self.assertEqual(portal.vmess_uri_for_user(vcfg, None, "1.2.3.4"), "")
        uri_v = portal.vmess_uri_for_user(vcfg, "u1", "1.2.3.4", label="my\r\nnode")
        payload = json.loads(base64.b64decode(uri_v[len("vmess://"):]).decode("utf-8"))
        self.assertNotIn("\r", payload["ps"])
        self.assertNotIn("\n", payload["ps"])

        acfg = {"domain": "node.example.com", "port": 8443, "secret": "good-sec"}
        self.assertEqual(portal.anytls_uri_for_user(acfg, None), "")
        self.assertEqual(portal.anytls_uri_for_user(dict(acfg, secret="bad\nsec"), "u1"), "")
        uri_a = portal.anytls_uri_for_user(acfg, "u1", label="a\nb")
        self.assertNotIn("%0A", uri_a)

        tcfg = {"domain": "node.example.com", "port": 41443, "secret": "good-sec"}
        self.assertEqual(portal.tuic_uri_for_user(tcfg, ""), "")
        self.assertEqual(portal.tuic_uri_for_user(dict(tcfg, secret="bad\rsec"), "u1"), "")
        uri_t = portal.tuic_uri_for_user(tcfg, "u1", label="t\rb")
        self.assertNotIn("%0D", uri_t)

        ecfg = {"domain": "node.example.com", "port": 8443, "encryption": "mlkem768x25519plus.native.0rtt.abc"}
        self.assertEqual(portal.vlessenc_uri_for_user(ecfg, None, "1.2.3.4"), "")
        uri_e = portal.vlessenc_uri_for_user(ecfg, "u1", "1.2.3.4", label="e\x07b")
        self.assertNotIn("%07", uri_e)

    def test_user_access_denial_rejects_fractional_limit_and_non_finite_now(self):
        """user_access_denial 不得把 0.5 字节限额截成 0（无限流量），且必须拒绝非有限/布尔 now。"""
        rec_frac = {"status": "active", "limit_bytes": 0.5, "used_bytes": 0}
        self.assertEqual(portal.user_access_denial(rec_frac, now=1000.0), "Invalid user record")

        rec_ok = {"status": "active", "expires_at": 2000, "limit_bytes": 100, "used_bytes": 10}
        self.assertIsNone(portal.user_access_denial(rec_ok, now=1000.0))
        self.assertEqual(portal.user_access_denial(rec_ok, now=float("-inf")), "Invalid user record")
        self.assertEqual(portal.user_access_denial(rec_ok, now=float("nan")), "Invalid user record")
        self.assertEqual(portal.user_access_denial(rec_ok, now=True), "Invalid user record")


if __name__ == "__main__":
    unittest.main()
