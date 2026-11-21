"""回归测试：出站探测（WARP 双端口回退、协议方案校验、重复前缀归一化、超时合法性）与出站模式状态口径一致。"""

import math
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class OutboundProbeAndStateConsistencyTests(unittest.TestCase):
    def test_ob_probe_warp_falls_back_to_legacy_40000(self):
        """_ob_probe 在 WARP 19898 不可用时应回退探测旧官方 127.0.0.1:40000 端口。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        probe_start = src.index('def _ob_probe(self):')
        probe_end = src.index('def _ob_manage(self):', probe_start)
        probe_body = src[probe_start:probe_end]
        self.assertIn("if kind == 'warp' and not ip:", probe_body)
        self.assertIn("detect_outbound_ip('socks5', '127.0.0.1:40000'", probe_body)

    def test_detect_outbound_ip_normalizes_socks5_prefix_and_blocks_non_http_schemes(self):
        """SOCKS5 已带 socks5:// 或 socks5h:// 时不得拼接重复前缀；HTTP 必须拦截非 http(s) 协议方案。"""
        captured = []

        def fake_run(args, **kwargs):
            captured.append((list(args), kwargs.get('input')))
            return SimpleNamespace(returncode=0, stdout='{"ip":"198.51.100.42"}', stderr='')

        with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ip = portal.detect_outbound_ip('socks5', 'socks5h://127.0.0.1:1080', timeout=4)
        self.assertEqual(ip, '198.51.100.42')
        self.assertEqual(captured[0][0][captured[0][0].index('--proxy') + 1], 'socks5h://127.0.0.1:1080')

        with mock.patch.object(portal.subprocess, 'run') as run_mock:
            self.assertEqual(portal.detect_outbound_ip('socks5', 'file:///etc/passwd'), '')
            self.assertEqual(portal.detect_outbound_ip('http', 'file:///etc/passwd'), '')
            self.assertEqual(portal.detect_outbound_ip('http', 'socks5://127.0.0.1:1080'), '')
            run_mock.assert_not_called()

    def test_detect_outbound_ip_rejects_bool_or_non_finite_timeout(self):
        """布尔或非有限超时值不得传入 curl 命令行。"""
        for bad_timeout in (True, False, math.nan, math.inf, -math.inf):
            with self.subTest(timeout=bad_timeout):
                with mock.patch.object(portal.subprocess, 'run') as run_mock:
                    self.assertEqual(portal.detect_outbound_ip('auto', timeout=bad_timeout), '')
                    run_mock.assert_not_called()

    def test_routing_state_sanitizes_invalid_outbound_mode(self):
        """routing_state 对非法字符串 outbound_mode 应回落为 rules。"""
        self.assertEqual(portal.routing_state({'outbound_mode': 'broken'})['outbound_mode'], 'rules')
        self.assertEqual(portal.routing_state({'outbound_mode': 123})['outbound_mode'], 'rules')
        self.assertEqual(portal.routing_state({'outbound_mode': 'global'})['outbound_mode'], 'global')

    def test_ob_list_and_warp_status_and_mode_switch_use_cleaned_state(self):
        """_ob_list / _h_get_warp_status / _ob_manage 切换 global 均应使用清洗后的出站与模式状态。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')

        ob_list_start = src.index('def _ob_list(self):')
        ob_list_end = src.index('def _ob_probe(self):', ob_list_start)
        ob_list_body = src[ob_list_start:ob_list_end]
        self.assertIn("mode = state['outbound_mode']", ob_list_body)

        warp_start = src.index('def _h_get_warp_status(self, subpath):')
        warp_end = src.index('def _h_get_cert_status(self, subpath):', warp_start)
        warp_body = src[warp_start:warp_end]
        self.assertIn("enabled = state['warp_enabled']", warp_body)
        self.assertIn("clean_outbounds(state['custom_outbounds'])", warp_body)

        manage_start = src.index('def _ob_manage(self):')
        manage_end = src.index('def _h_get_warp_status(self, subpath):', manage_start)
        manage_body = src[manage_start:manage_end]
        self.assertIn("valid_outs = clean_outbounds(routing_state(data)['custom_outbounds'])", manage_body)


if __name__ == '__main__':
    unittest.main()
