"""订阅里的节点字段必须是客户端真正认识的写法（2026-11-03 修）。

SE 上用真客户端校验过生成的订阅：
  * mihomo v1.19.15：Reality 节点写成 tls={...} / reality_opts 时整份 clash.yaml
    加载失败（"'tls' expected type 'bool'"）。
  * sing-box 1.14.4：VLESS 出站带 encryption 时 sing-box.json 报 unknown field，
    整份订阅不可用，连 Hy2 节点一起丢。
这里锁住字段形态；真客户端不在 CI 里。
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

META = {'server_name': 'node.example.com', 'public_ip': '192.0.2.1', 'listen_port': 443,
        'auth_password': 'pw', 'obfs_password': 'o', 'is_insecure': False,
        'hop_port_range': '', 'subscription_port': 8443}
REALITY = {'enabled': True, 'port': 8444, 'dest_sni': 'www.apple.com',
           'public_key': 'Z' * 43, 'short_id': 'abcd1234', 'uri': 'x'}
VLESSENC = {'enabled': True, 'port': 2088, 'domain': 'node.example.com',
            'encryption': 'mlkem768x25519plus.native.0rtt.KbaHNHMC_tiG2Ia8R-U-K1HLV25DhsYTlctMsXJdriY',
            'decryption': 'x'}


def proxies(clash):
    return {p['name']: p for p in json.loads(clash)['proxies']}


class SubscriptionSchemaTests(unittest.TestCase):
    def setUp(self):
        _, self.clash, self.sing = portal.artifacts(META, reality=REALITY, vlessenc=VLESSENC,
                                                    user_id='buyer')

    def test_clash_reality_uses_mihomo_field_names(self):
        p = next(v for k, v in proxies(self.clash).items() if k.endswith('-Reality'))
        self.assertIs(p['tls'], True)
        self.assertEqual(p['reality-opts'], {'public-key': 'Z' * 43, 'short-id': 'abcd1234'})
        self.assertNotIn('reality_opts', p)
        self.assertEqual(p['servername'], 'www.apple.com')

    def test_clash_still_offers_vless_encryption(self):
        self.assertTrue(any(k.endswith('-VLESS-Enc') for k in proxies(self.clash)))


if __name__ == '__main__':
    unittest.main()
