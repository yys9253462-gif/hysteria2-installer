"""回归测试：Xray 计量配置非字典入参清晰报错、重复 API 规则与黑洞去重、binary 参数校验与 enable_reality_online 客户端不变式。"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MOD_PATH = ROOT / 'usage-meter-xray-config-20261007-v1.py'
SPEC = importlib.util.spec_from_file_location('usage_meter_xray_config_test_mod', MOD_PATH)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class XrayConfigBinaryDedupDictAndClientsGuardsTests(unittest.TestCase):
    def test_add_iplimit_routing_and_api_rule_first_reject_non_dict_with_value_error(self):
        """add_iplimit_routing 与 api_rule_first 遇到非字典配置应抛 ValueError 而非 AttributeError。"""
        for bad in (None, [], 'bad', 123):
            with self.assertRaises(ValueError):
                MOD.add_iplimit_routing(bad)
            with self.assertRaises(ValueError):
                MOD.api_rule_first(bad)

    def test_api_rule_first_deduplicates_multiple_api_rules(self):
        """routing.rules 中若已存在多条重复 API_RULE，api_rule_first 必须去重为首条唯一规则并返回 True。"""
        cfg = {
            'routing': {
                'rules': [
                    dict(MOD.API_RULE),
                    {'type': 'field', 'ip': ['127.0.0.0/8'], 'outboundTag': 'block-private'},
                    dict(MOD.API_RULE),
                ]
            }
        }
        changed = MOD.api_rule_first(cfg)
        self.assertTrue(changed)
        self.assertEqual(cfg['routing']['rules'].count(MOD.API_RULE), 1)
        self.assertEqual(cfg['routing']['rules'][0], MOD.API_RULE)

    def test_add_iplimit_routing_deduplicates_multiple_iplimit_block_outbounds(self):
        """outbounds 中存在多个重复 iplimit-block 出站时应归并为单条非首位 blackhole。"""
        cfg = {
            'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
            'outbounds': [
                {'protocol': 'freedom', 'tag': 'direct'},
                {'protocol': 'freedom', 'tag': MOD.IPLIMIT_OUTBOUND_TAG},
                {'protocol': 'blackhole', 'tag': MOD.IPLIMIT_OUTBOUND_TAG},
            ],
        }
        MOD.add_iplimit_routing(cfg)
        matched = [o for o in cfg['outbounds'] if isinstance(o, dict) and o.get('tag') == MOD.IPLIMIT_OUTBOUND_TAG]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]['protocol'], 'blackhole')
        self.assertNotEqual(cfg['outbounds'][0].get('tag'), MOD.IPLIMIT_OUTBOUND_TAG)

    def test_enable_helpers_reject_invalid_binary_and_protect_clients(self):
        """enable_iplimit_routing 与 enable_reality_online 必须拒绝非法 binary 参数，且 enable_reality_online 须校验 clients 不变式。"""
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text(json.dumps({
                'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
                'inbounds': [],
                'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            }), encoding='utf-8')
            for bad_bin in ('', '   ', '-evil', '/usr/bin/xray\x00bad', None, 123):
                with self.assertRaises(ValueError, msg=f'enable_iplimit_routing 应拒绝非法 binary={bad_bin!r}'):
                    MOD.enable_iplimit_routing(cfg_path, bad_bin, '127.0.0.1:19997')
                with self.assertRaises(ValueError, msg=f'enable_reality_online 应拒绝非法 binary={bad_bin!r}'):
                    MOD.enable_reality_online(cfg_path, bad_bin, '127.0.0.1:19997')

        src = MOD_PATH.read_text(encoding='utf-8')
        fn_src = src[src.index('def enable_reality_online('):]
        self.assertIn('must not modify inbound clients', fn_src)


if __name__ == '__main__':
    unittest.main()
