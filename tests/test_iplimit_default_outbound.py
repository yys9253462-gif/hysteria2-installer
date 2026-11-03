"""首个出站就是托管黑洞时，补路由不能把黑洞复制成默认出站（2026-11-04 修）。"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('xcfg_default', ROOT / 'usage-meter-xray-config-20261007-v1.py')
xcfg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xcfg)


class IplimitDefaultOutboundTests(unittest.TestCase):
    def test_leading_managed_blackhole_does_not_become_default(self):
        cfg = {'api': {'tag': 'usage-meter-api', 'services': []},
               'outbounds': [{'protocol': 'blackhole', 'tag': xcfg.IPLIMIT_OUTBOUND_TAG}]}
        out = xcfg.add_iplimit_routing(cfg)['outbounds']
        self.assertNotEqual(out[0]['protocol'], 'blackhole')
        self.assertEqual(sum(o.get('tag') == xcfg.IPLIMIT_OUTBOUND_TAG for o in out), 1)

    def test_leading_misused_tag_keeps_original_egress(self):
        cfg = {'api': {'tag': 'usage-meter-api', 'services': []},
               'outbounds': [{'protocol': 'socks', 'tag': xcfg.IPLIMIT_OUTBOUND_TAG, 'settings': {'x': 1}}]}
        out = xcfg.add_iplimit_routing(cfg)['outbounds']
        self.assertEqual(out[0]['protocol'], 'socks')
        self.assertNotIn('tag', out[0])


if __name__ == '__main__':
    unittest.main()
