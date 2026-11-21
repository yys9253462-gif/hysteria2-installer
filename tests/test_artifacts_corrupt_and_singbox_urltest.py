"""回归测试：artifacts() 容忍损坏的非对象协议配置，且 sing-box 仅在有真实备用出站时才追加 urltest。"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class ArtifactsCorruptAndSingboxUrltestTests(unittest.TestCase):
    def _base_meta(self):
        return {
            'is_insecure': False,
            'server_name': 'node.example.com',
            'public_ip': '198.51.100.10',
            'listen_port': 443,
            'auth_password': 'secret-password',
        }

    def test_corrupt_non_dict_protocol_configs_do_not_crash_artifacts(self):
        """vmess / vlessenc / anytls / tuic 若被改坏为非 dict 或含非字符串字段，artifacts() 必须平稳跳过。"""
        uri, clash_raw, sing_raw = portal.artifacts(
            self._base_meta(),
            user_id='u1',
            reality='broken-string',
            vmess=['not', 'a', 'dict'],
            vlessenc=12345,
            anytls=True,
            tuic='bad',
        )
        self.assertTrue(uri.startswith('hysteria2://'))
        clash = json.loads(clash_raw)
        sing = json.loads(sing_raw)
        self.assertEqual(len(clash['proxies']), 1)
        self.assertEqual(len(sing['outbounds']), 1)

    def test_corrupt_field_types_inside_protocol_dicts_are_skipped_safely(self):
        """协议配置为 dict 但 domain/secret/encryption 为非字符串时，不得抛 TypeError 或 AttributeError。"""
        uri, clash_raw, sing_raw = portal.artifacts(
            self._base_meta(),
            user_id='u1',
            vmess={'domain': 123, 'port': 443, 'sni': ['bad'], 'ws_path': 999},
            vlessenc={'domain': 'node.example.com', 'port': 8443, 'encryption': ['bad']},
            anytls={'domain': 'node.example.com', 'port': 2096, 'secret': 12345},
            tuic={'domain': ['bad'], 'port': 41000, 'secret': 'ok-secret'},
        )
        self.assertTrue(uri.startswith('hysteria2://'))
        self.assertEqual(len(json.loads(clash_raw)['proxies']), 1)
        self.assertEqual(len(json.loads(sing_raw)['outbounds']), 1)

    def test_singbox_omits_urltest_when_only_vlessenc_is_enabled(self):
        """仅启用 Hy2 + VLESS-Enc 时，sing-box 实际只有 1 条 Hy2 出站，不应生成冗余单节点 urltest 组。"""
        _, clash_raw, sing_raw = portal.artifacts(
            self._base_meta(),
            user_id='u1',
            vlessenc={
                'domain': 'node.example.com',
                'port': 8443,
                'sni': 'node.example.com',
                'encryption': 'mlkem768x25519plus.native.0rtt.testkey',
            },
        )
        clash = json.loads(clash_raw)
        sing = json.loads(sing_raw)
        # Clash 侧有 Hy2 + VLESS-Enc 两条，仍应使用 url-test
        self.assertEqual(len(clash['proxies']), 2)
        self.assertEqual(clash['proxy-groups'][0]['type'], 'url-test')
        # sing-box 侧只有 Hy2 一条，绝不能附加只有 1 个出站的 urltest 和 route
        self.assertEqual(len(sing['outbounds']), 1, f'sing-box 不应生成单节点 urltest: {sing}')
        self.assertNotIn('route', sing)


if __name__ == '__main__':
    unittest.main()
