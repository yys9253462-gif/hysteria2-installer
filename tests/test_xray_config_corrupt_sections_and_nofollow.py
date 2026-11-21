"""回归测试：usage-meter-xray-config-20261007-v1.py 对损坏配置段、Unicode 数字端口的防御及私有写盘 O_NOFOLLOW 加固。"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_mod():
    spec = importlib.util.spec_from_file_location('um_xray_cfg', ROOT / 'usage-meter-xray-config-20261007-v1.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class XrayConfigCorruptSectionsAndNofollowTests(unittest.TestCase):
    def test_validate_loopback_address_rejects_unicode_digits(self):
        """回环地址端口必须为纯 ASCII 数字，不得放行全角数字等 Unicode isdigit() 字符。"""
        mod = _load_mod()
        for bad in ('127.0.0.1:１９９９７', '127.0.0.1:²²', '127.0.0.1:019997'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    mod._validate_loopback_address(bad)

    def test_add_stats_handles_null_settings_policy_and_non_dict_entries(self):
        """inbounds 含 settings:null、policy:null 或非对象 api/routing 时应安全处理或明确抛 ValueError（不得 AttributeError）。"""
        mod = _load_mod()
        cfg = {
            'policy': None,
            'routing': None,
            'inbounds': [
                {'tag': 'dok', 'protocol': 'dokodemo-door', 'settings': None},
                {'tag': 'real', 'protocol': 'vless', 'settings': {'clients': [{'id': 'u1', 'level': 0}]}},
            ],
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
        }
        out = mod.add_stats(cfg, 19997)
        self.assertIn('StatsService', out['api']['services'])
        self.assertEqual(out['inbounds'][1]['settings']['clients'], [{'id': 'u1', 'level': 0}])

        # api / inbounds 为非法的非对象/非列表类型时应抛 ValueError 而非 AttributeError/TypeError
        with self.assertRaises(ValueError):
            mod.add_stats({'api': 'broken'}, 19997)
        with self.assertRaises(ValueError):
            mod.add_stats({'inbounds': 'broken'}, 19997)

    def test_iplimit_routing_ready_handles_corrupt_outbounds_and_routing(self):
        """outbounds/routing/api 被改坏成非对象或含非对象元素时 iplimit_routing_ready 返回 False 而不崩溃。"""
        mod = _load_mod()
        for bad_cfg in (
            {'api': 'bad', 'outbounds': 'bad', 'routing': 'bad'},
            {'api': {'services': ['RoutingService']}, 'outbounds': [None, 'bad'], 'routing': {'rules': 'bad'}},
        ):
            with self.subTest(bad_cfg=bad_cfg):
                self.assertFalse(mod.iplimit_routing_ready(bad_cfg))

    def test_enable_reality_online_handles_null_settings_and_policy(self):
        """enable_reality_online 遇到 settings:null 与 policy:null 时不得抛 AttributeError。"""
        mod = _load_mod()
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text(json.dumps({
                'policy': None,
                'inbounds': [{'tag': 'a', 'settings': None}],
            }), encoding='utf-8')
            with mock.patch.object(mod.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')):
                res = mod.enable_reality_online(cfg_path, '/usr/local/bin/xray', '127.0.0.1:19997')
            self.assertTrue(res['enabled'])
            self.assertTrue(res['changed'])

    def test_write_private_bytes_uses_o_nofollow_when_available(self):
        """_write_private_bytes 源码应使用 O_NOFOLLOW 防止临时路径符号链接覆写。"""
        src = (ROOT / 'usage-meter-xray-config-20261007-v1.py').read_text(encoding='utf-8')
        self.assertIn('O_NOFOLLOW', src)


if __name__ == '__main__':
    unittest.main()
