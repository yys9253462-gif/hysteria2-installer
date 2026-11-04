"""托管协议选端口时避开 gost 代理服务的端口（2026-11-04 修）。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ReservedPortsProxyTests(unittest.TestCase):
    def test_proxy_service_ports_are_reserved(self):
        data = {'proxy_services': [{'port': 34567}, {'port': 'bad'}, 'junk']}
        self.assertIn(34567, portal.managed_reserved_ports({}, data))

    def test_damaged_container_is_ignored(self):
        self.assertEqual(portal.managed_reserved_ports({}, {'proxy_services': 7}), set())


if __name__ == '__main__':
    unittest.main()
