"""回归测试：usage-meter-readers 对非对象负载、非 UTF-8 日志字节及 HTTPError 句柄关闭的防护。"""

import importlib.util
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_readers():
    path = ROOT / 'usage-meter-readers-20261007-v1.py'
    spec = importlib.util.spec_from_file_location('usage_meter_readers_mod', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterReadersHardeningTests(unittest.TestCase):
    def test_parse_xray_rejects_non_dict_root_and_rows_with_value_error(self):
        """parse_xray 遇到非对象根或非对象行时必须统一抛 ValueError，不得泄出 AttributeError。"""
        mod = _load_readers()
        for bad in ('[]', '"str"', 'null', '{"stat": ["not-a-dict"]}', '{"stat": [{"name": 123}]}'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    mod.parse_xray(bad)

    def test_parse_events_survives_non_utf8_bytes_and_rejects_malformed_rows_as_value_error(self):
        """journald MESSAGE 含非法 UTF-8 字节不得抛 UnicodeDecodeError；畸形行应转为 ValueError。"""
        mod = _load_readers()
        # 含非法 UTF-8 字节 0xff 的普通日志行（非连接事件）应平滑跳过而非崩溃
        rows = [{'__MONOTONIC_TIMESTAMP': '100', 'MESSAGE': [0x68, 0x69, 0xff, 0x0a]}]
        self.assertEqual(mod.parse_events(rows), {})

        with self.assertRaises(ValueError):
            mod.parse_events(['not-a-dict'])
        with self.assertRaises(ValueError):
            mod.parse_events([{'__MONOTONIC_TIMESTAMP': 'not-int', 'MESSAGE': 'hi'}])

    def test_read_live_connections_closes_404_http_error_and_handles_corrupt_cfg(self):
        """/online/ips 返回 404 回退时必须关闭 HTTPError 句柄，且非对象 xray policy 不得抛 AttributeError。"""
        mod = _load_readers()
        closed = []

        class Fake404(urllib.error.HTTPError):
            def __init__(self):
                super().__init__('http://127.0.0.1:19996/online/ips', 404, 'Not Found', {}, None)

            def close(self):
                closed.append(True)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg_p = root / 'usage-meter-config.json'
            portal_p = root / 'portal.json'
            xray_p = root / 'xray.json'
            xray_bin = root / 'xray'
            xray_bin.write_text('#!/bin/sh\n', encoding='utf-8')
            cfg_p.write_text(json.dumps({
                'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'},
                'reality': {'binary': str(xray_bin), 'address': '127.0.0.1:19997'},
            }), encoding='utf-8')
            portal_p.write_text(json.dumps({'users': {'u1': {}}}), encoding='utf-8')
            # 刻意构造非 dict 的 policy 节点
            xray_p.write_text(json.dumps({'policy': ['broken']}), encoding='utf-8')

            real_path = Path

            def fake_path(p):
                s = str(p)
                if s == '/etc/hysteria/usage-meter-config.json':
                    return cfg_p
                if s == '/etc/hysteria/portal.json':
                    return portal_p
                if s == '/etc/hysteria/xray.json':
                    return xray_p
                return real_path(p)

            with mock.patch.object(mod, 'pathlib', SimpleNamespace(Path=fake_path)), \
                 mock.patch.object(mod.urllib.request, 'urlopen', side_effect=Fake404()), \
                 mock.patch.object(mod, 'read_hysteria_online', return_value={'u1': 0}), \
                 mock.patch.object(mod, 'service_running', return_value=True):
                res = mod.read_live_connections()

            self.assertEqual(closed, [True], '404 HTTPError 句柄未被关闭')
            self.assertTrue(res['users']['u1']['hysteria_ok'])
            self.assertFalse(res['users']['u1']['reality_ok'])
            self.assertIn('online_statistics_not_enabled', res['users']['u1']['reality_error'])


if __name__ == '__main__':
    unittest.main()
