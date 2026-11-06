"""订阅生成对 client_meta.json 里改坏的字段先清洗（2026-11-06 修）。

server_name / public_ip 为数字、列表或 null，is_insecure 写成字符串，hop_port_range 为乱码
或倒序时，旧实现照样输出 `server: 123`、`skip-cert-verify: 'false'`、`server_ports: ["garbage"]`，
YAML / JSON 都能解析，客户端却拒收或连错。直接调用 artifacts() 并解析输出。
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

BASE = {'server_name': 'ex.com', 'public_ip': '1.2.3.4', 'listen_port': 443, 'auth_password': 'p'}


def parsed(meta):
    uri, clash, sing = portal.artifacts(meta)
    sing_obj = json.loads(sing)
    out = next(o for o in sing_obj['outbounds'] if o.get('type') == 'hysteria2')
    proxy = yaml.safe_load(clash)['proxies'][0] if yaml else None
    return uri, proxy, out


class ArtifactsCleanMetaTests(unittest.TestCase):
    def test_non_string_hosts_fall_back_to_strings(self):
        for extra in ({'server_name': 123}, {'server_name': ['x']},
                      {'server_name': None, 'public_ip': None}):
            with self.subTest(extra=extra):
                uri, proxy, out = parsed(dict(BASE, **extra))
                self.assertIsInstance(out['server'], str)
                self.assertIsInstance(out['tls']['server_name'], str)
                self.assertNotIn('None', uri)
                self.assertNotIn("['x']", uri)
                if proxy is not None:
                    self.assertIsInstance(proxy['server'], str)
                    self.assertIsInstance(proxy['sni'], str)

    def test_string_insecure_becomes_a_real_bool(self):
        for flag, want in (('false', False), ('true', True), ('False', False)):
            with self.subTest(flag=flag):
                _, proxy, out = parsed(dict(BASE, is_insecure=flag))
                self.assertIs(out['tls']['insecure'], want)
                if proxy is not None:
                    self.assertIs(proxy['skip-cert-verify'], want)

    def test_bad_hop_ranges_are_dropped_and_good_ones_normalized(self):
        for bad in ('garbage', '40000-20000', '0-5', '1-99999'):
            with self.subTest(bad=bad):
                uri, proxy, out = parsed(dict(BASE, hop_port_range=bad))
                self.assertNotIn('mport', uri)
                self.assertNotIn('server_ports', out)
        uri, proxy, out = parsed(dict(BASE, hop_port_range='20000:40000'))
        self.assertIn('mport=20000-40000', uri)
        self.assertEqual(out['server_ports'], ['443:443', '20000:40000'])
        if proxy is not None:
            self.assertEqual(proxy['ports'], '443,20000-40000')


class SharePageHostTests(unittest.TestCase):
    """分享页与订阅同一套 meta 清洗（2026-11-06 修）：server_name 为数字时分享页曾 500。"""
    def test_display_host_is_always_a_string(self):
        for meta in ({'server_name': 123, 'public_ip': '1.2.3.4'},
                     {'server_name': 'www.bing.com', 'public_ip': None, 'is_insecure': True},
                     {'server_name': 'ex.com', 'public_ip': '1.2.3.4', 'is_insecure': 'false'}):
            with self.subTest(meta=meta):
                host = portal.meta_display_host(meta)
                self.assertIsInstance(host, str)
        self.assertEqual(portal.meta_display_host({'server_name': 'ex.com', 'public_ip': '1.2.3.4',
                                                   'is_insecure': 'false'}), 'ex.com')
        page = portal.user_page_html('x', portal.meta_display_host({'server_name': 123}), 443, '', 'u',
                                     {'used_bytes': 0}, 'hysteria2://a@b:1', 'c', '{}', '', 't', 'k', 8443)
        self.assertIn('<!doctype html', page.lower())


class RealityParamsTests(unittest.TestCase):
    """Reality 的 sni / 公钥 / short_id 改坏时不出错误节点（2026-11-06 修）。"""
    GOOD = {'port': 443, 'dest_sni': 'www.apple.com', 'public_key': 'AbC-123_xyz', 'short_id': '0012'}

    def nodes(self, rcfg):
        uri, clash, sing = portal.artifacts(BASE, reality=rcfg, user_id='bob')
        return [o for o in json.loads(sing)['outbounds'] if o.get('type') == 'vless']

    def test_valid_config_still_yields_a_node(self):
        out = self.nodes(self.GOOD)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['tls']['reality']['short_id'], '0012')
        self.assertIn('sid=0012', portal.reality_uri_for_user(self.GOOD, 'bob', '1.2.3.4'))

    def test_corrupt_fields_drop_the_node(self):
        for bad in ({'dest_sni': 123}, {'dest_sni': 'a b&c'}, {'public_key': 5},
                    {'short_id': 12}, {'short_id': 'ab#cd'}):
            with self.subTest(bad=bad):
                rcfg = dict(self.GOOD, **bad)
                self.assertEqual(self.nodes(rcfg), [])
                self.assertEqual(portal.reality_uri_for_user(rcfg, 'bob', '1.2.3.4'), '')


class ProtocolHostTests(unittest.TestCase):
    """VMess / VLESS-Enc / AnyTLS / TUIC 直链的 domain / sni 改坏时不拼出假地址（2026-11-06 修）。"""
    def test_corrupt_domain_and_sni(self):
        import base64
        vm = portal.vmess_uri_for_user({'port': 2087, 'domain': 123, 'sni': ['x'], 'ws_path': '/p'}, 'bob', '1.2.3.4')
        doc = json.loads(base64.b64decode(vm[len('vmess://'):] + '==').decode())
        self.assertEqual((doc['add'], doc['sni']), ('1.2.3.4', '1.2.3.4'))
        self.assertIn('sni=1.2.3.4', portal.vlessenc_uri_for_user(
            {'port': 2088, 'domain': None, 'sni': 5, 'encryption': 'e'}, 'bob', '1.2.3.4'))
        self.assertEqual(portal.anytls_uri_for_user({'port': 2096, 'domain': 7, 'secret': 's', 'enabled': True}, 'bob'), '')
        self.assertEqual(portal.tuic_uri_for_user({'port': 41000, 'domain': ['d'], 'secret': 's', 'enabled': True}, 'bob'), '')
        self.assertIn('@n.example.com:41000?sni=n.example.com', portal.tuic_uri_for_user(
            {'port': 41000, 'domain': 'n.example.com', 'sni': 1, 'secret': 's', 'enabled': True}, 'bob'))


if __name__ == '__main__':
    unittest.main()
