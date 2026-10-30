"""端口探测失败及损坏配置不能生成错误订阅。"""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


class PortProbeBoundaries(unittest.TestCase):
    def test_failed_ss_commands_do_not_claim_success_or_parse_stderr_output(self):
        result = subprocess.CompletedProcess([], 1, 'LISTEN 0 128 0.0.0.0:443 *:*', 'permission denied')
        with patch.object(portal.subprocess, 'run', return_value=result):
            self.assertEqual(portal._listening_ports_detail(), (set(), False))

    def test_one_successful_ss_command_still_counts_as_probe(self):
        results = [subprocess.CompletedProcess([], 1, '', 'unavailable'),
                   subprocess.CompletedProcess([], 0, 'UNCONN 0 0 0.0.0.0:19984 *:*', '')]
        with patch.object(portal.subprocess, 'run', side_effect=results):
            self.assertEqual(portal._listening_ports_detail(), ({19984}, True))

    def test_infinite_preferred_port_falls_back_without_exception(self):
        with patch.object(portal, '_listening_ports', return_value=set()):
            for bad in (float('inf'), float('-inf')):
                with self.subTest(bad=bad):
                    port, _ = portal._pick_reality_port(bad)
                    self.assertGreater(port, 0)
                    self.assertLessEqual(port, 65535)

    def test_invalid_subscription_port_uses_valid_default(self):
        meta = {'server_name': 'node.example.com', 'auth_password': 'test'}
        for bad in (True, 443.5, float('inf')):
            with self.subTest(bad=bad):
                uri, clash, sing = portal.artifacts(dict(meta, listen_port=bad))
                self.assertIn(':19984?', uri)
                doc = json.loads(sing)
                self.assertEqual(doc['outbounds'][0]['server_port'], 19984)

    def test_corrupt_subscription_port_is_not_used_for_links(self):
        """订阅端口 True/1.5/inf 不能被当成 1 或截断，否则链接指向没人监听的端口。"""
        for bad in (True, 1.5, float('inf'), 70000, -1):
            with self.subTest(bad=bad):
                port, source = portal.resolve_subscription_port(
                    {'subscription_port': bad}, '/nonexistent/config.yaml')
                self.assertEqual(source, 'fallback')
                self.assertEqual(port, 443)

    def test_numeric_string_subscription_port_still_honoured(self):
        self.assertEqual(portal.resolve_subscription_port(
            {'subscription_port': '2053'}, '/nonexistent/config.yaml'), (2053, 'client_meta'))


class ReservedPortTests(unittest.TestCase):
    """端口避让清单对损坏的 meta/data 不能抛异常。

    它在三个协议的启用流程里：异常会让「启用」直接失败，
    而界面只显示一句「启用失败」，看不出是配置坏了。
    """

    def test_corrupt_meta_and_data_do_not_raise(self):
        for meta in (None, 7, 'x', [None], {}):
            for data in (None, 7, 'x', {}, {'reality_config': 7}, {'anytls_config': 'x'}):
                with self.subTest(meta=meta, data=data):
                    portal.managed_reserved_ports(meta, data, None)

    def test_ports_are_collected_from_meta_and_protocol_configs(self):
        meta = {'listen_port': 443, 'subscription_port': 8443}
        data = {'vmess_config': {'port': 2087},
                'vlessenc_config': {'port': 2088},
                'anytls_config': {'enabled': True, 'port': 2089}}
        self.assertEqual(portal.managed_reserved_ports(meta, data, None),
                         {443, 8443, 2087, 2088, 2089})

    def test_disabled_anytls_port_is_not_reserved(self):
        data = {'anytls_config': {'enabled': False, 'port': 2089}}
        self.assertEqual(portal.managed_reserved_ports({}, data, None), set())

    def test_excluded_protocol_port_is_not_reserved(self):
        data = {'vmess_config': {'port': 2087}}
        self.assertEqual(portal.managed_reserved_ports({}, data, None,
                                                       exclude_key='vmess_config'), set())


if __name__ == '__main__':
    unittest.main()
