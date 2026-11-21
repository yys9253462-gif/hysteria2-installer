"""回归测试：validate_outbound 必须支持 [IPv6]:port SOCKS5 出站，拦截控制字符与越界 HTTP 端口。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class ValidateOutboundIpv6AndControlsTests(unittest.TestCase):
    def test_socks5_accepts_valid_bracketed_ipv6_and_rejects_invalid_ipv6(self):
        """SOCKS5 出站应接受合法 [IPv6]:port，同时拒绝非法方括号地址与控制字符。"""
        ok, cleaned, err = portal.validate_outbound({
            'name': 'v6_proxy',
            'type': 'socks5',
            'addr': '[2001:db8::1]:1080',
        })
        self.assertTrue(ok, f'合法 IPv6 SOCKS5 地址被误拒: {err}')
        self.assertEqual(cleaned['addr'], '[2001:db8::1]:1080')

        for bad_addr in ('[not-an-ip]:1080', '1.2.3.4\x00:1080', '[2001:db8::1]:70000'):
            with self.subTest(bad_addr=bad_addr):
                ok_bad, _, _ = portal.validate_outbound({
                    'name': 'bad_proxy',
                    'type': 'socks5',
                    'addr': bad_addr,
                })
                self.assertFalse(ok_bad, f'非法地址 {bad_addr!r} 不应放行')

    def test_http_outbound_rejects_control_chars_and_out_of_range_port(self):
        """HTTP 出站必须拦截控制字符（如 NUL）与越界端口（如 :99999），避免写坏 config.yaml。"""
        for bad_url in (
            'http://1.2.3.4:99999',
            'https://proxy.example.com:0',
            'http://proxy.example.com:8080/\x00evil',
            'http://:8080',
        ):
            with self.subTest(bad_url=bad_url):
                ok, _, _ = portal.validate_outbound({
                    'name': 'bad_http',
                    'type': 'http',
                    'url': bad_url,
                })
                self.assertFalse(ok, f'非法 HTTP 出站 URL {bad_url!r} 不应放行')

        ok_good, cleaned, err = portal.validate_outbound({
            'name': 'good_http',
            'type': 'http',
            'url': 'https://user:pass@[2001:db8::1]:8443',
        })
        self.assertTrue(ok_good, err)
        self.assertEqual(cleaned['url'], 'https://user:pass@[2001:db8::1]:8443')


if __name__ == '__main__':
    unittest.main()
