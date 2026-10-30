import unittest
from unittest.mock import patch

import sys  # noqa: E402
# 🔴 2026-10-31：CI 用的是 `python3 -m unittest discover -s tests -p 'test_*.py'`，
# 那条命令会把 CWD（仓库根）放进 sys.path；而「文档里教的、人最常敲的」
# `cd tests && python3 -m unittest test_xxx` 不会。用后一种方式时这六个文件
# 报 ModuleNotFoundError: No module named 'portal' —— 看着像代码坏了，其实是
# 加载方式差异。这里补上与其它 38 个测试一致的路径注入，两种跑法都能过。
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))

import portal


class OutboundRuleTests(unittest.TestCase):
    def test_direct_rule_stays_direct_when_warp_is_installed(self):
        with patch.object(portal, "_existing_outbound_names", return_value=["direct_ipv4", "warp_socks"]):
            acl = portal.build_acl_block(
                "rules", [{"domain": "example.com", "outbound": "direct"}], [], "direct_ipv4")
        self.assertIn("direct(suffix:example.com)", acl)
        self.assertNotIn("warp_socks(suffix:example.com)", acl)

    def test_configured_builtin_and_custom_targets_are_preserved(self):
        with patch.object(portal, "_existing_outbound_names", return_value=["warp_socks"]):
            builtin = portal.build_acl_block(
                "rules", [{"domain": "example.com", "outbound": "warp_socks"}], [], "direct")
            custom = portal.build_acl_block(
                "rules", [{"domain": "example.com", "outbound": "proxy_1"}],
                [{"name": "proxy_1", "type": "socks5"}], "direct")
        self.assertIn("warp_socks(suffix:example.com)", builtin)
        self.assertIn("proxy_1(suffix:example.com)", custom)

    def test_missing_legacy_target_uses_existing_fallback(self):
        with patch.object(portal, "_existing_outbound_names", return_value=["warp_socks"]):
            acl = portal.build_acl_block(
                "rules", [{"domain": "example.com", "outbound": "removed_proxy"}], [], "direct")
        self.assertIn("warp_socks(suffix:example.com)", acl)

    def test_target_validation_accepts_only_real_or_acl_builtin_names(self):
        self.assertTrue(portal.outbound_target_exists("direct", [], []))
        self.assertTrue(portal.outbound_target_exists("reject", [], []))
        self.assertTrue(portal.outbound_target_exists(
            "proxy_1", [{"name": "proxy_1"}], []))
        self.assertTrue(portal.outbound_target_exists("warp_socks", [], ["warp_socks"]))
        self.assertFalse(portal.outbound_target_exists("typo_proxy", [], ["warp_socks"]))


if __name__ == "__main__":
    unittest.main()
