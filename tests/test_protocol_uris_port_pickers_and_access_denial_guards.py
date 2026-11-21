"""回归测试：托管协议直链控制字符与非字符串 label 防护、端口挑选器溢出与全角数字防御及布尔 expires_at 判定。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class ProtocolUrisPortPickersAndAccessDenialGuardsTests(unittest.TestCase):
    def test_protocol_host_sni_rejects_control_chars_and_whitespace(self):
        """protocol_host_sni 必须拒绝含换行/控制字符/内部空白的 domain 与 sni。"""
        host, sni = portal.protocol_host_sni(
            {'domain': 'bad.example.com\nevil', 'sni': 'bad sni'},
            fallback='203.0.113.10',
        )
        self.assertEqual((host, sni), ('203.0.113.10', '203.0.113.10'))

        host2, sni2 = portal.protocol_host_sni(
            {'domain': 'ok.example.com', 'sni': 'evil\r\nheader'},
            fallback='203.0.113.10',
        )
        self.assertEqual((host2, sni2), ('ok.example.com', 'ok.example.com'))

    def test_vmess_vlessenc_anytls_tuic_uris_handle_bad_fields_and_non_string_label(self):
        """四大托管协议直链函数对坏 ws_path/encryption 返回空串，对非字符串 label 不得抛 TypeError。"""
        self.assertEqual(
            portal.vmess_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'ws_path': '/ws\r\nevil'}, 'u1', '1.2.3.4'),
            '',
        )
        self.assertEqual(
            portal.vmess_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'ws_path': 123}, 'u1', '1.2.3.4'),
            '',
        )
        self.assertEqual(
            portal.vlessenc_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'encryption': 'abc\ndef'}, 'u1', '1.2.3.4'),
            '',
        )
        self.assertEqual(
            portal.vlessenc_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'encryption': 999}, 'u1', '1.2.3.4'),
            '',
        )

        # 非字符串 label 必须安全回退默认标签，不抛 TypeError
        self.assertTrue(
            portal.vmess_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'ws_path': '/ws'}, 'u1', '1.2.3.4', label=123).startswith('vmess://')
        )
        self.assertTrue(
            portal.vlessenc_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'encryption': 'mlkem768'}, 'u1', '1.2.3.4', label=123).startswith('vless://')
        )
        self.assertTrue(
            portal.anytls_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'secret': 'sec'}, 'u1', label=123).startswith('anytls://')
        )
        self.assertTrue(
            portal.tuic_uri_for_user({'domain': 'a.example.com', 'port': 8443, 'secret': 'sec'}, 'u1', label=123).startswith('tuic://')
        )

    def test_pick_tuic_port_and_pick_reality_port_reject_inf_float_and_fullwidth(self):
        """pick_tuic_port 与 pick_reality_port 不得因 inf 抛 OverflowError，且须拒绝小数与全角数字偏好端口。"""
        # pick_tuic_port 面对 inf/小数/全角数字 preferred 与含 inf 的 blocked 必须优雅跳过
        p1 = portal.pick_tuic_port(float('inf'), [float('inf'), True, 'bad'], listening=set())
        self.assertTrue(portal.TUIC_PORT_RANGE[0] <= p1 <= portal.TUIC_PORT_RANGE[1])

        p2 = portal.pick_tuic_port(10080.9, [], listening=set())
        self.assertNotEqual(p2, 10080, '小数端口 10080.9 不得被静默截断采纳')

        p3 = portal.pick_tuic_port('１００８０', [], listening=set())
        self.assertNotEqual(p3, 10080, '全角数字端口不得被采纳')

        # _pick_reality_port 不得采纳全角数字偏好端口
        from unittest import mock
        with mock.patch.object(portal, '_listening_ports', return_value=set()):
            rp, _ = portal._pick_reality_port(preferred='８４４３', default=2053)
        self.assertEqual(rp, 2053, '_pick_reality_port 不得采纳全角数字偏好端口')

    def test_user_access_denial_rejects_boolean_expires_at_as_invalid_record(self):
        """expires_at 为布尔值（True/False）必须返回 Invalid user record，而非误判为已过期。"""
        self.assertEqual(
            portal.user_access_denial({'status': 'active', 'expires_at': True}, now=1000),
            'Invalid user record',
        )
        self.assertEqual(
            portal.user_access_denial({'status': 'active', 'expires_at': False}, now=1000),
            'Invalid user record',
        )


if __name__ == '__main__':
    unittest.main()
