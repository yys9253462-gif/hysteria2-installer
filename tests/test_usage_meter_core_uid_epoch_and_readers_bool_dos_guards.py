"""回归测试：usage-meter-core 非法 uid/空白 epoch 与 usage-meter-readers 非 ASCII secret、超长数字、非字符串地址与布尔 count。"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CORE = _load("um_core_t57_8", "usage-meter-core-20261007-v1.py")
READERS = _load("um_readers_t57_8", "usage-meter-readers-20261007-v1.py")


class UsageMeterCoreAndReadersGuardTests(unittest.TestCase):
    """验证计量核心与读取器的 5 组边界防护。"""

    def test_core_rejects_empty_uid_unhashable_uid_and_whitespace_epoch(self):
        """total_bytes/adjusted_bytes 拒不可哈希或空 uid；apply_sample 拒空 uid 与空白/控制字符 epoch。"""
        with self.assertRaises(ValueError):
            CORE.total_bytes({"totals": {}}, ["not-hashable"])
        with self.assertRaises(ValueError):
            CORE.adjusted_bytes({"totals": {}, "adjustments": {}}, {"k": "v"})
        with self.assertRaises(ValueError):
            CORE.total_bytes({"totals": {}}, "")

        with self.assertRaises(ValueError):
            CORE.apply_sample({}, "hysteria", "   ", {}, "2026-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            CORE.apply_sample({}, "hysteria", "ep\n1", {}, "2026-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            CORE.apply_sample({}, "hysteria", "ep1", {"": {"tx": 1, "rx": 1}}, "2026-01-01T00:00:00Z")

    def test_readers_loopback_base_rejects_non_ascii_secret_and_whitespace_or_control_url(self):
        """_validate_loopback_http_base 必须拒绝非 ASCII secret、控制字符与含空白 URL。"""
        with self.assertRaises(ValueError):
            READERS._validate_loopback_http_base("http://127.0.0.1:9999", "中文密钥")
        with self.assertRaises(ValueError):
            READERS._validate_loopback_http_base("http://127.0.0.1:9999", "bad\x07secret")
        with self.assertRaises(ValueError):
            READERS._validate_loopback_http_base(" http://127.0.0.1:9999 ", "ok")
        with self.assertRaises(ValueError):
            READERS._validate_loopback_http_base("http://127.0.0.1:9999\x1f", "ok")

    def test_parse_xray_rejects_non_text_and_overlong_digit_strings(self):
        """parse_xray 拒绝非字符串/字节入参及超长数字字符串。"""
        with self.assertRaises(ValueError):
            READERS.parse_xray(None)
        huge_val = "9" * 5000
        raw = '{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":"' + huge_val + '"}]}'
        with self.assertRaises(ValueError) as ctx:
            READERS.parse_xray(raw)
        self.assertIn("invalid xray counter", str(ctx.exception))

    def test_norm_ip_and_addr_ip_reject_non_str_and_overlong_port_digits(self):
        """_norm_ip 与 _addr_ip 拒绝非字符串入参，且超长端口数字应按端口非法拒绝而非触发 int 超限异常。"""
        with self.assertRaises(ValueError):
            READERS._norm_ip(12345)
        with self.assertRaises(ValueError):
            READERS._addr_ip(None)

        huge_port = "9" * 5000
        with self.assertRaises(ValueError) as ctx1:
            READERS._addr_ip(f"1.2.3.4:{huge_port}")
        self.assertEqual(str(ctx1.exception), "invalid_addr_port")

        with self.assertRaises(ValueError) as ctx2:
            READERS._addr_ip(f"[::1]:{huge_port}")
        self.assertEqual(str(ctx2.exception), "invalid_bracketed_port")

    def test_parse_events_rejects_non_sequence_and_confirmed_ips_rejects_bool_count(self):
        """parse_events 拒非列表/元组入参；confirmed_ips 对布尔/负数 count 必须返回 None（fail-closed）。"""
        with self.assertRaises(ValueError):
            READERS.parse_events("not-a-list")
        with self.assertRaises(ValueError):
            READERS.parse_events({"a": 1})

        conns = {("u1", "1.2.3.4"): 1}
        self.assertIsNone(READERS.confirmed_ips(conns, "u1", False), "False 不得等价于 0 判为空在线列表")
        self.assertIsNone(READERS.confirmed_ips(conns, "u1", True), "True 不得等价于 1 判为 1 台在线")
        self.assertIsNone(READERS.confirmed_ips(conns, "u1", -1))
        self.assertIsNone(READERS.confirmed_ips("not-dict", "u1", 0))
        self.assertEqual(READERS.confirmed_ips(conns, "u1", 1), ["1.2.3.4"])


if __name__ == "__main__":
    unittest.main()
