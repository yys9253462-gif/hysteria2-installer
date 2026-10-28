"""计量 API 的回环路由必须排在内网拦截规则之前（2026-10-28）。

内网拦截规则的 ip 含 127.0.0.0/8；它若排在 API 规则前面，
发往 127.0.0.1:19997 的统计调用会进黑洞，Reality 计量与设备上限静默失效
（斯德哥尔摩、香港、洛杉矶实测）。
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

_spec = importlib.util.spec_from_file_location('meter_xray_cfg', ROOT / 'usage-meter-xray-config-20261007-v1.py')
xcfg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(xcfg)

API_RULE = {'type': 'field', 'inboundTag': ['usage-meter-api-in'], 'outboundTag': 'usage-meter-api'}


def guard_rule():
    return {'type': 'field', 'ip': list(portal.XRAY_PRIVATE_REJECT_IPS), 'outboundTag': portal.XRAY_BLOCK_OUTBOUND_TAG}


def base_config():
    return {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            'inbounds': [{'tag': 'usage-meter-api-in', 'listen': '127.0.0.1', 'port': 19997,
                          'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'}}],
            'api': {'tag': 'usage-meter-api', 'services': ['StatsService', 'RoutingService']}}


class GuardOrderTests(unittest.TestCase):
    def test_guard_after_stats_keeps_api_first(self):
        # Reality 生成的实际顺序：先 add_stats，再 add_private_network_guard。
        cfg = xcfg.add_stats({'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}, 19997)
        cfg = portal.add_private_network_guard(cfg)
        rules = cfg['routing']['rules']
        self.assertEqual(rules[0], API_RULE)
        self.assertEqual(rules[1]['outboundTag'], 'block-private')

    def test_stats_after_guard_keeps_api_first(self):
        cfg = portal.add_private_network_guard({'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]})
        cfg = xcfg.add_stats(cfg, 19997)
        self.assertEqual(cfg['routing']['rules'][0], API_RULE)

    def test_guard_repairs_broken_order_and_is_idempotent(self):
        cfg = base_config()
        cfg['routing'] = {'rules': [guard_rule(), API_RULE, {'type': 'field', 'domain': ['x'], 'outboundTag': 'direct'}]}
        once = portal.add_private_network_guard(cfg)
        twice = portal.add_private_network_guard(once)
        rules = twice['routing']['rules']
        self.assertEqual(rules[0], API_RULE)
        self.assertEqual(rules[1]['outboundTag'], 'block-private')
        self.assertEqual(len(rules), 3, '不能重复追加或丢掉其它规则')

    def test_broken_order_is_not_ready_and_gets_repaired(self):
        # 生产上已经写坏的 xray.json：拦截在前。iplimit worker 据 ready 判断是否重写。
        cfg = base_config()
        cfg['outbounds'].append({'protocol': 'blackhole', 'tag': xcfg.IPLIMIT_OUTBOUND_TAG})
        cfg['routing'] = {'rules': [guard_rule(), API_RULE]}
        self.assertFalse(xcfg.iplimit_routing_ready(cfg), '顺序错了必须判为未就绪，才会触发修复')
        self.assertTrue(xcfg.api_rule_first(cfg))
        self.assertEqual(cfg['routing']['rules'][0], API_RULE)
        self.assertTrue(xcfg.iplimit_routing_ready(cfg))
        self.assertFalse(xcfg.api_rule_first(cfg), '已经正确时不应再改')


if __name__ == '__main__':
    unittest.main()
