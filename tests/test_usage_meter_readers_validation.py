"""回归测试：usage-meter-readers 对回环 URL/secret/Xray 地址端口的严格校验与日志时间戳布尔/空值防护。"""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_readers():
    path = ROOT / 'usage-meter-readers-20261007-v1.py'
    spec = importlib.util.spec_from_file_location('usage_meter_readers_validation_mod', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterReadersValidationTests(unittest.TestCase):
    def test_hysteria_readers_reject_query_fragment_userinfo_or_bad_secret(self):
        mod = _load_readers()
        for fn in (mod.read_hysteria, mod.read_hysteria_online):
            for bad_url in (
                'http://127.0.0.1:9999?x=1',
                'http://127.0.0.1:9999#frag',
                'http://user:pass@127.0.0.1:9999',
                'http://127.0.0.1:9999;p=1',
                123,
            ):
                with self.subTest(fn=fn.__name__, bad_url=bad_url):
                    with self.assertRaises(ValueError):
                        fn(bad_url, 'sec')
            for bad_secret in (None, 123, 'bad\r\nX-Inject: 1', 'bad\n'):
                with self.subTest(fn=fn.__name__, bad_secret=bad_secret):
                    with self.assertRaises(ValueError):
                        fn('http://127.0.0.1:9999', bad_secret)

    def test_read_xray_rejects_invalid_loopback_port_or_non_string_address(self):
        mod = _load_readers()
        for bad_addr in (
            None,
            12345,
            '127.0.0.1:',
            '127.0.0.1:0',
            '127.0.0.1:65536',
            '127.0.0.1:10085 --extra',
            '127.0.0.1:abc',
        ):
            with self.subTest(bad_addr=bad_addr):
                with self.assertRaises(ValueError):
                    mod.read_xray('/usr/local/bin/xray', bad_addr)

    def test_parse_events_falls_back_when_monotonic_is_none_and_rejects_bool_timestamp(self):
        mod = _load_readers()
        # __MONOTONIC_TIMESTAMP 为 None 时应回退到 __REALTIME_TIMESTAMP，而非 int(None) 崩溃
        rows = [
            {'__MONOTONIC_TIMESTAMP': None, '__REALTIME_TIMESTAMP': '200', 'MESSAGE': 'plain log'},
            {'__MONOTONIC_TIMESTAMP': None, '__REALTIME_TIMESTAMP': '100', 'MESSAGE': 'plain log'},
        ]
        self.assertEqual(mod.parse_events(rows), {})

        # 布尔值不得被当成时间戳 1/0
        with self.assertRaises(ValueError):
            mod.parse_events([{'__MONOTONIC_TIMESTAMP': True, 'MESSAGE': 'plain log'}])


if __name__ == '__main__':
    unittest.main()
