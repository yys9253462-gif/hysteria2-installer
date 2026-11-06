"""选新端口时避开停用协议保留的端口（2026-11-06 修）。

Reality / VMess / VLESS Encryption 停用后保留端口，再启用要沿用；旧实现选端口时跳过停用段，
别的协议可能占走它，再启用时只能换端口，已发的订阅全部指错。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ReservedPortsKeepDisabledTests(unittest.TestCase):
    DATA = {'vlessenc_config': {'enabled': False, 'port': 2053},
            'vmess_config': {'enabled': False, 'port': 2087}}

    def test_picking_a_port_avoids_disabled_siblings(self):
        got = portal.managed_reserved_ports({}, self.DATA, exclude_key='reality_config', keep_disabled=True)
        self.assertIn(2053, got)
        self.assertIn(2087, got)

    def test_own_kept_port_is_still_excluded(self):
        got = portal.managed_reserved_ports({}, self.DATA, exclude_key='vlessenc_config', keep_disabled=True)
        self.assertNotIn(2053, got)
        self.assertIn(2087, got)

    def test_in_use_check_still_ignores_disabled_sections(self):
        self.assertEqual(portal.managed_reserved_ports({}, self.DATA), set())


if __name__ == '__main__':
    unittest.main()
