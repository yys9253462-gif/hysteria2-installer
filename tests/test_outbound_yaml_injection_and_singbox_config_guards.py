"""回归测试：出站 YAML 注入防护、clean_outbounds 必填字段过滤、空出站段防脏写、SOCKS5 前导零端口与 AnyTLS/TUIC 配置校验。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class OutboundYamlInjectionAndSingboxConfigGuardsTests(unittest.TestCase):
    def test_yaml_scalar_and_render_outbound_block_newline_injection(self):
        """_yaml_scalar 与 render_outbound_yaml 的 direct.mode 均不得向 YAML 注入换行或新配置项。"""
        rendered_scalar = portal._yaml_scalar("safe\n  - name: evil\r\n")
        self.assertNotIn('\n', rendered_scalar)
        self.assertNotIn('\r', rendered_scalar)

        injected_direct = {
            'name': 'my_direct',
            'type': 'direct',
            'mode': 'auto\n  - name: evil\n    type: direct',
        }
        yaml_text = portal.render_outbound_yaml(injected_direct)
        self.assertNotIn('evil', yaml_text, '非法 direct.mode 不得原样拼进 YAML 触发配置注入')
        self.assertIn('mode: auto', yaml_text)

    def test_clean_outbounds_drops_missing_addr_or_url_and_upsert_skips_empty_block(self):
        """clean_outbounds 必须过滤缺少 addr/url 或含换行的坏出站；全坏时 upsert 不得写出空 outbounds: 段。"""
        rows = [
            {'name': 'bad_socks_missing', 'type': 'socks5'},
            {'name': 'bad_socks_ctrl', 'type': 'socks5', 'addr': '1.2.3.4:1080\nevil: 1'},
            {'name': 'bad_http_missing', 'type': 'http'},
            {'name': 'bad_http_non_str', 'type': 'http', 'url': 12345},
            {'name': 'bad_http_ctrl', 'type': 'http', 'url': 'http://1.2.3.4:8080\r\nevil'},
            {'name': 'good_direct', 'type': 'direct'},
            {'name': 'good_socks', 'type': 'socks5', 'addr': '1.2.3.4:1080'},
            {'name': 'good_http', 'type': 'http', 'url': 'http://1.2.3.4:8080'},
        ]
        cleaned = portal.clean_outbounds(rows)
        self.assertEqual(
            [o['name'] for o in cleaned],
            ['good_direct', 'good_socks', 'good_http'],
        )
        # 全部条目都无效时，upsert_outbound_block 不得在原配置末尾拼出孤立的空 outbounds:
        base_cfg = 'listen: :443\n'
        updated = portal.upsert_outbound_block(base_cfg, rows[:5])
        self.assertNotIn('outbounds:', updated, '所有自定义出站都被过滤后不得写出孤立的空 outbounds: 键')

    def test_validate_outbound_rejects_leading_zero_port_and_slash_host(self):
        """validate_outbound 必须拒绝 SOCKS5 端口前导零与含斜杠/特殊分隔符的主机。"""
        for bad_addr in ('1.2.3.4:01080', '[::1]:00443', '1.2.3.4/path:1080', 'a@b:1080'):
            ok, _, err = portal.validate_outbound({
                'name': 'my_socks',
                'type': 'socks5',
                'addr': bad_addr,
            })
            self.assertFalse(ok, f'非法 SOCKS5 地址 {bad_addr!r} 应被拒绝，实际通过: {err}')

    def test_build_anytls_and_tuic_config_validate_port_and_coerce_server_name(self):
        """build_anytls_config / build_tuic_config 必须校验端口合法性并清洗非字符串 server_name。"""
        for fn in (portal.build_anytls_config, portal.build_tuic_config):
            for bad_cfg in (
                'not-a-dict',
                {'port': 0, 'domain': 'a.example.com'},
                {'port': True, 'domain': 'a.example.com'},
                {'port': 70000, 'domain': 'a.example.com'},
                {'port': 'bad', 'domain': 'a.example.com'},
            ):
                with self.assertRaises(ValueError, msg=f'{fn.__name__} 应拒绝非法配置 {bad_cfg!r}'):
                    fn(bad_cfg, [], '/c.pem', '/k.pem')

            cfg = fn({'port': '8443', 'sni': 123, 'domain': 'ok.example.com'}, [], '/c.pem', '/k.pem')
            inbound = cfg['inbounds'][0]
            self.assertEqual(inbound['listen_port'], 8443)
            self.assertEqual(inbound['tls']['server_name'], 'ok.example.com')

            cfg_empty = fn({'port': 8443, 'sni': None, 'domain': ['bad']}, [], '/c.pem', '/k.pem')
            self.assertEqual(cfg_empty['inbounds'][0]['tls']['server_name'], '')


if __name__ == '__main__':
    unittest.main()
