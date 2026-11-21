"""回归测试：usage-meter-readers 纯 ASCII 端口/计数校验、方括号地址尾缀与 Xray 在线时间戳边界防护。"""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_readers():
    path = ROOT / 'usage-meter-readers-20261007-v1.py'
    spec = importlib.util.spec_from_file_location('usage_meter_readers_edge_guards_mod', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterReadersEdgeGuardsTests(unittest.TestCase):
    def test_validate_xray_addr_and_parse_xray_reject_non_ascii_digits(self):
        """Xray 回环地址端口与统计数值必须为纯 ASCII 数字，拒绝全角数字绕过。"""
        mod = _load_readers()
        with self.assertRaises(ValueError):
            mod._validate_loopback_xray_addr('127.0.0.1:\uff11\uff10\uff10\uff18\uff15')
        with self.assertRaises(ValueError):
            mod.parse_xray(json.dumps({
                'stat': [{'name': 'user>>>u1>>>traffic>>>uplink', 'value': '\uff11\uff12\uff13'}]
            }))

    def test_read_xray_validates_binary_and_rejects_oversized_stdout(self):
        """read_xray 必须拒绝空/非字符串/含空字节的 binary，并拦截超限输出。"""
        mod = _load_readers()
        for bad_bin in ('', None, 123, '/usr/bin/xray\x00evil'):
            with self.subTest(bad_bin=bad_bin):
                with self.assertRaises(ValueError):
                    mod.read_xray(bad_bin, '127.0.0.1:10085')
        oversized = mock.Mock(stdout=b' ' * (8 * 1024 * 1024 + 10))
        with mock.patch.object(mod.subprocess, 'run', return_value=oversized):
            with self.assertRaises(ValueError):
                mod.read_xray('/usr/local/bin/xray', '127.0.0.1:10085')

    def test_addr_ip_rejects_bracketed_trailing_garbage(self):
        """方括号 IPv6 地址后若跟非合法 :port 尾缀必须报 ValueError，不得静默放行。"""
        mod = _load_readers()
        self.assertEqual(mod._addr_ip('[2001:db8::1]'), '2001:db8::1')
        self.assertEqual(mod._addr_ip('[2001:db8::1]:443'), '2001:db8::1')
        for bad in ('[2001:db8::1]garbage', '[2001:db8::1]:0', '[2001:db8::1]:99999', '[2001:db8::1]:abc'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    mod._addr_ip(bad)

    def test_read_live_connections_rejects_negative_or_nan_reality_seen_timestamp(self):
        """Xray statsonlineiplist 返回负数、NaN/Inf 或全角时间戳时，不得写入非法 last_seen。"""
        mod = _load_readers()
        cfg = {
            'hysteria': {'url': 'http://127.0.0.1:9999', 'secret': 's'},
            'reality': {'binary': '/usr/local/bin/xray', 'address': '127.0.0.1:10085'},
        }
        portal_data = {'users': {'u1': {'status': 'active'}}}
        xray_cfg = {'policy': {'levels': {'0': {'statsUserOnline': True}}}}

        def fake_read_text(self_path, *a, **kw):
            name = Path(self_path).name
            if name == 'usage-meter-config.json':
                return json.dumps(cfg)
            if name == 'portal.json':
                return json.dumps(portal_data)
            if name == 'xray.json':
                return json.dumps(xray_cfg)
            raise FileNotFoundError(name)

        class _LiveResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1):
                return json.dumps({'revision': 'teyir-live-ips-v1', 'users': {'u1': {'connections': 0, 'ips': []}}}).encode()

        for bad_seen in (-5, float('nan'), float('inf'), '\uff11\uff12\uff13', 12.5):
            def fake_cmd(args, _seen=bad_seen):
                if 'statsgetallonlineusers' in args:
                    return json.dumps({'users': ['user>>>u1>>>online']})
                if 'statsonlineiplist' in args:
                    return json.dumps({'ips': {'1.2.3.4': _seen}}, allow_nan=True)
                return ''

            with self.subTest(bad_seen=bad_seen):
                with mock.patch.object(mod.pathlib.Path, 'read_text', fake_read_text), \
                        mock.patch.object(mod.pathlib.Path, 'is_file', return_value=True), \
                        mock.patch.object(mod.urllib.request, 'urlopen', return_value=_LiveResp()), \
                        mock.patch.object(mod, 'service_running', return_value=True), \
                        mock.patch.object(mod, 'cmd', side_effect=fake_cmd):
                    res = mod.read_live_connections()['users']['u1']
                self.assertFalse(res['reality_ok'], f'非法时间戳 {bad_seen!r} 不应让 reality_ok=True')
                self.assertEqual([x for x in res['ips'] if x['protocol'] == 'Reality'], [])


if __name__ == '__main__':
    unittest.main()
