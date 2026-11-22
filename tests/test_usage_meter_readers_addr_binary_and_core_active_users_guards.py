"""回归测试：计量采集器端口/地址/binary 路径与输出上限校验，以及核心 apply_sample 的 active_users 不可哈希元素拦截。"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CORE = _load('usage_meter_core_t55', 'usage-meter-core-20261007-v1.py')
READERS = _load('usage_meter_readers_t55', 'usage-meter-readers-20261007-v1.py')


class UsageMeterReadersAddrBinaryAndCoreActiveUsersGuardsTests(unittest.TestCase):
    def test_addr_ip_and_loopback_xray_addr_reject_bad_and_leading_zero_ports(self):
        """_addr_ip 须校验 IPv4:port 的端口合法性，_validate_loopback_xray_addr 须拒绝前导零端口。"""
        self.assertEqual(READERS._addr_ip('198.51.100.1:443'), '198.51.100.1')
        self.assertEqual(READERS._addr_ip('[2001:db8::1]:8443'), '2001:db8::1')
        self.assertEqual(READERS._addr_ip('2001:db8::1'), '2001:db8::1')
        for bad in (
            '198.51.100.1:abc',
            '198.51.100.1:99999',
            '198.51.100.1:080',
            '198.51.100.1:0',
            '[2001:db8::1]:080',
        ):
            with self.assertRaises(ValueError, msg=f'应拒绝畸形地址 {bad!r}'):
                READERS._addr_ip(bad)

        with self.assertRaises(ValueError):
            READERS._validate_loopback_xray_addr('127.0.0.1:08080')
        self.assertEqual(READERS._validate_loopback_xray_addr('127.0.0.1:8080'), '127.0.0.1:8080')

    def test_read_xray_rejects_dash_and_control_char_binary(self):
        """read_xray 须拒绝以 - 开头或含换行控制字符的 binary 路径。"""
        for bad in ('-evil', '/usr/bin/xray\n--help', ' \t '):
            with self.assertRaises(ValueError, msg=f'应拒绝非法 binary={bad!r}'):
                READERS.read_xray(bad, '127.0.0.1:10085')

    def test_read_live_connections_survives_null_byte_binary_in_reality_config(self):
        """reality.binary 含 \\x00 时不得在 try 外抛 ValueError 炸毁整个 Hy2 快照，应优雅降级。"""
        with tempfile.TemporaryDirectory() as td:
            cfg_p = Path(td) / 'usage-meter-config.json'
            portal_p = Path(td) / 'portal.json'
            cfg_p.write_text(json.dumps({
                'hysteria': {'url': 'http://127.0.0.1:9999', 'secret': 'sec'},
                'reality': {'binary': '/usr/local/bin/xray\x00bad', 'address': '127.0.0.1:10085'},
            }), encoding='utf-8')
            portal_p.write_text(json.dumps({'users': {'alice': {'status': 'active'}}}), encoding='utf-8')

            real_path = Path

            def fake_path(p):
                if str(p) == '/etc/hysteria/usage-meter-config.json':
                    return cfg_p
                if str(p) == '/etc/hysteria/portal.json':
                    return portal_p
                return real_path(p)

            class _Resp:
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return False
                def read(self, n=-1):
                    return json.dumps({
                        'revision': 'teyir-live-ips-v1',
                        'users': {'alice': {'connections': 1, 'ips': ['198.51.100.7']}},
                    }).encode('utf-8')

            with patch.object(READERS.pathlib, 'Path', side_effect=fake_path), \
                 patch.object(READERS.urllib.request, 'urlopen', return_value=_Resp()):
                snap = READERS.read_live_connections()
            self.assertTrue(snap['users']['alice']['hysteria_ok'])
            self.assertEqual(snap['users']['alice']['ips'][0]['ip'], '198.51.100.7')

    def test_apply_sample_rejects_unhashable_active_users_with_value_error(self):
        """apply_sample 收到含不可哈希元素（如 dict）的 active_users 须抛 ValueError 而非 TypeError。"""
        state = {}
        with self.assertRaises(ValueError):
            CORE.apply_sample(state, 'hysteria', 'ep1', {}, '2026-11-22T00:00:00Z', active_users=[{'bad': 1}])

        # 同时校验损坏的 previous.baseline_at 不会被延续
        state2 = {
            'sources': {
                'hysteria': {
                    'epoch': 'ep1',
                    'counters': {},
                    'sampled_at': '2026-11-22T00:00:00Z',
                    'baseline_at': float('nan'),
                }
            }
        }
        CORE.apply_sample(state2, 'hysteria', 'ep1', {}, '2026-11-22T00:01:00Z')
        self.assertNotIn('baseline_at', state2['sources']['hysteria'])


if __name__ == '__main__':
    unittest.main()
