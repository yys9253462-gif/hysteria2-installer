"""回归测试：usage-meter-xray-config 超长数字/脏出站/配置文件防符号链接与体积上限，以及 usage-meter-core 空白 epoch 与控制字符拦截。"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XRAY_CFG_PATH = ROOT / 'usage-meter-xray-config-20261007-v1.py'
CORE_PATH = ROOT / 'usage-meter-core-20261007-v1.py'


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterXrayConfigAndCoreGuardsTests(unittest.TestCase):
    def setUp(self):
        self.xcfg = _load('xcfg_guard_59', XRAY_CFG_PATH)
        self.core = _load('core_guard_59', CORE_PATH)

    def test_xray_config_caps_huge_digits_in_level_port_and_address(self):
        """_client_level_key、_inbound_uses_port 与 _validate_loopback_address 面对 >4300 位超长数字不得抛 ValueError 崩溃。"""
        huge = '9' * 5000
        self.assertIsNone(self.xcfg._client_level_key(huge))
        self.assertEqual(self.xcfg._client_level_key('12'), '12')
        self.assertFalse(self.xcfg._inbound_uses_port(huge, 19997))
        self.assertFalse(self.xcfg._inbound_uses_port('1-' + huge, 19997))
        self.assertTrue(self.xcfg._inbound_uses_port('19990-20000', 19997))
        with self.assertRaises(ValueError):
            self.xcfg._validate_loopback_address('127.0.0.1:' + huge)
        src = XRAY_CFG_PATH.read_text(encoding='utf-8')
        fn_addr = src[src.index('def _validate_loopback_address'):src.index('def _validate_binary')]
        self.assertIn('len(port_text)', fn_addr)

    def test_add_iplimit_routing_drops_non_dict_corrupt_outbounds_before_picking_default(self):
        """outbounds 含非 dict 脏项（尤其在首位）时，add_iplimit_routing 须清理脏项并保证合法默认出站在首位。"""
        cfg = {
            'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
            'outbounds': [None, 'bad', {'protocol': 'blackhole', 'tag': 'iplimit-block'}],
        }
        self.xcfg.add_iplimit_routing(cfg)
        self.assertTrue(all(isinstance(o, dict) for o in cfg['outbounds']))
        self.assertEqual(cfg['outbounds'][0]['protocol'], 'freedom')
        self.assertEqual(cfg['outbounds'][-1]['tag'], 'iplimit-block')

    def test_enable_iplimit_and_reality_online_reject_symlink_and_oversized_config(self):
        """enable_iplimit_routing 与 enable_reality_online 须拒绝符号链接、目录与超过 4 MiB 的配置文件。"""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / 'as_dir'
            d.mkdir()
            for fn in (self.xcfg.enable_iplimit_routing, self.xcfg.enable_reality_online):
                with self.subTest(fn=fn.__name__, kind='dir'):
                    with self.assertRaises(ValueError):
                        fn(str(d), '/usr/local/bin/xray', '127.0.0.1:19997')

            big = Path(td) / 'big.json'
            big.write_bytes(b' ' * (4 * 1024 * 1024 + 16))
            for fn in (self.xcfg.enable_iplimit_routing, self.xcfg.enable_reality_online):
                with self.subTest(fn=fn.__name__, kind='oversized'):
                    with self.assertRaises(ValueError):
                        fn(str(big), '/usr/local/bin/xray', '127.0.0.1:19997')

            real = Path(td) / 'real.json'
            real.write_text('{}', encoding='utf-8')
            link = Path(td) / 'link.json'
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                pass
            else:
                for fn in (self.xcfg.enable_iplimit_routing, self.xcfg.enable_reality_online):
                    with self.subTest(fn=fn.__name__, kind='symlink'):
                        with self.assertRaises(ValueError):
                            fn(str(link), '/usr/local/bin/xray', '127.0.0.1:19997')

        src = XRAY_CFG_PATH.read_text(encoding='utf-8')
        self.assertIn('lstat()', src)
        self.assertIn('S_ISREG', src)

    def test_core_apply_sample_rejects_whitespace_epoch_control_chars_and_corrupt_adjustments(self):
        """apply_sample 须拒绝含空白的 epoch、含控制字符的 sampled_at / uid 以及非字典 adjustments。"""
        with self.assertRaises(ValueError):
            self.core.apply_sample({}, 'hysteria', 'ep 1', {}, '2026-11-22T00:00:00Z')
        with self.assertRaises(ValueError):
            self.core.apply_sample({}, 'hysteria', 'ep1', {}, '2026-11-22\nFAKE')
        with self.assertRaises(ValueError):
            self.core.apply_sample({}, 'hysteria', 'ep1', {'alice\r\n': {'tx': 1, 'rx': 2}}, '2026-11-22T00:00:00Z')
        with self.assertRaises(ValueError):
            self.core.apply_sample({'adjustments': ['bad']}, 'hysteria', 'ep1', {'alice': {'tx': 1, 'rx': 2}}, '2026-11-22T00:00:00Z')


if __name__ == '__main__':
    unittest.main()
