"""回归测试：节点标识控制字符清洗、跳跃端口前导零、Reality 链接容错、备用协议脏字段过滤与二维码/初始化校验。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class ArtifactsIdentityBackupProtocolsAndQrGuardsTests(unittest.TestCase):
    def test_clean_node_identity_rejects_control_chars_and_embedded_whitespace(self):
        """clean_node_identity 必须丢弃含换行/控制字符/中间空白的损坏 server_name 或 public_ip。"""
        _, sn, ip, host = portal.clean_node_identity({
            'server_name': 'good.example.com\nevil',
            'public_ip': '203.0.113.10',
            'is_insecure': False,
        })
        self.assertEqual(sn, '203.0.113.10')
        self.assertEqual(ip, '203.0.113.10')
        self.assertEqual(host, '203.0.113.10')

        _, sn2, ip2, host2 = portal.clean_node_identity({
            'server_name': 'bad host name',
            'public_ip': '1.2.3.4\r\n',
            'is_insecure': True,
        })
        self.assertEqual((sn2, ip2, host2), ('localhost', 'localhost', 'localhost'))

    def test_clean_hop_range_rejects_leading_zeros(self):
        """clean_hop_range 必须拒绝带前导零的端口区间。"""
        self.assertIsNone(portal.clean_hop_range('08080-40000'))
        self.assertIsNone(portal.clean_hop_range('8080-09000'))
        self.assertEqual(portal.clean_hop_range('20000-40000'), (20000, 40000))

    def test_reality_uri_handles_non_string_label_and_bad_public_ip(self):
        """reality_uri_for_user 对非字符串 label 不得抛 TypeError，对脏 public_ip 返回空串。"""
        rcfg = {
            'port': 8443,
            'dest_sni': 'www.apple.com',
            'public_key': 'AbCdEf123456',
            'short_id': '00ab12',
        }
        uri = portal.reality_uri_for_user(rcfg, 'alice', '203.0.113.10', label=12345)
        self.assertTrue(uri.startswith('vless://'))
        self.assertEqual(portal.reality_uri_for_user(rcfg, 'alice', '203.0.113.10\nevil'), '')
        self.assertEqual(portal.reality_uri_for_user(rcfg, 'alice', ''), '')

    def test_artifacts_drops_backup_protocols_with_control_chars_or_whitespace(self):
        """artifacts() 面对含换行/空白的备用协议 domain/ws_path/encryption 须跳过坏节点而非污染整份订阅。"""
        meta = {'server_name': 'node.example.com', 'public_ip': '203.0.113.10', 'listen_port': 443, 'auth_password': 'pw'}
        uri, clash_str, sing_str = portal.artifacts(
            meta,
            user_id='alice',
            vmess={'domain': 'vm.example.com\nevil', 'port': 8444, 'ws_path': '/ws'},
            vlessenc={'domain': 've.example.com', 'port': 8445, 'encryption': 'mlkem768\nbad'},
            anytls={'domain': 'at.example.com', 'sni': 'bad\nsni', 'port': 8446, 'secret': 'sec123'},
            tuic={'domain': 'tu ic.example.com', 'port': 8447, 'secret': 'sec456'},
        )
        self.assertTrue(uri.startswith('hysteria2://'))
        clash = json.loads(clash_str)
        names = [p['name'] for p in clash['proxies']]
        self.assertNotIn('Hy2-node.example.com-VMess', names)
        self.assertNotIn('Hy2-node.example.com-VLESS-Enc', names)
        self.assertNotIn('Hy2-node.example.com-TUIC', names)
        # AnyTLS domain 合法，坏 sni 应安全回落到干净 domain
        anytls_nodes = [p for p in clash['proxies'] if p['type'] == 'anytls']
        self.assertEqual(len(anytls_nodes), 1)
        self.assertEqual(anytls_nodes[0]['sni'], 'at.example.com')
        # 合法 VMess 若 ws_path 含换行也必须拦截
        _, clash_str2, _ = portal.artifacts(
            meta,
            user_id='alice',
            vmess={'domain': 'vm.example.com', 'port': 8444, 'ws_path': '/ws\r\nX-Injected: 1'},
        )
        self.assertNotIn('vmess', [p['type'] for p in json.loads(clash_str2)['proxies']])

    def test_qr_svg_for_and_prepare_validate_svg_and_auth_password(self):
        """qr_svg_for 须拒绝非 SVG 输出，prepare 须校验 client_meta 含有效 auth_password 且拒非 SVG 二维码。"""
        with mock.patch.object(
            portal.subprocess, 'run',
            return_value=subprocess.CompletedProcess(['qrencode'], 0, stdout=b'warning: not svg', stderr=b''),
        ):
            self.assertIsNone(portal.qr_svg_for('hysteria2://test'))

        with tempfile.TemporaryDirectory() as td:
            meta_p = Path(td) / 'client_meta.json'
            meta_p.write_text(json.dumps({
                'server_name': 'node.example.com',
                'public_ip': '203.0.113.10',
                'listen_port': 443,
            }), encoding='utf-8')
            with self.assertRaises(ValueError) as ctx:
                portal.prepare(str(meta_p), 28080)
            self.assertIn('auth_password', str(ctx.exception))

            meta_p.write_text(json.dumps({
                'server_name': 'node.example.com',
                'public_ip': '203.0.113.10',
                'listen_port': 443,
                'auth_password': 'secret_master_pw',
            }), encoding='utf-8')
            with mock.patch.object(portal, 'sync_cert_trust'), \
                 mock.patch.object(portal, 'sync_pin'), \
                 mock.patch.object(portal, 'resolve_subscription_port', return_value=(443, 'test')), \
                 mock.patch.object(
                     portal.subprocess, 'run',
                     return_value=subprocess.CompletedProcess(['qrencode'], 0, stdout=b'plain text error', stderr=b''),
                 ):
                portal.prepare(str(meta_p), 28080)
            saved = json.loads((Path(td) / 'portal.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['qr'], '', 'prepare() 不得把非 SVG 文本写入 portal.json["qr"]')


if __name__ == '__main__':
    unittest.main()
