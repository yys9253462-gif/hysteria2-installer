import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PANEL_JOIN = REPO / 'panel-join.py'
SPEC = importlib.util.spec_from_file_location('panel_join_b51', PANEL_JOIN)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class TestPanelJoinInlineAcmeHostAndUrlGuards(unittest.TestCase):
    def test_acme_first_domain_supports_inline_list_and_ignores_acme_prefix_keys(self):
        """acme_first_domain 必须支持行内列表 domains: [...] 且不误把 acme_extra: 当作 acme: 段。"""
        cfg_inline = (
            'acme_extra:\n'
            '  domains:\n'
            '    - wrong.example.com\n'
            'acme:\n'
            '  domains: ["node1.example.com", "node2.example.com"] # inline\n'
        )
        self.assertEqual(MOD.acme_first_domain(cfg_inline), 'node1.example.com')

    def test_meta_host_rejects_invalid_host_chars_and_read_handles_directory(self):
        """meta_host 须拒绝含空格/路径/控制字符的非法主机名，read 遇目录须返回 None 而非抛异常。"""
        bad_meta = json.dumps({'server_name': 'evil.com/path?x=1', 'public_ip': '1.2.3.4'})
        self.assertEqual(MOD.meta_host(bad_meta), '1.2.3.4')
        all_bad = json.dumps({'server_name': 'bad host', 'public_ip': 'bad\n1.2.3.4'})
        self.assertEqual(MOD.meta_host(all_bad), '')
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(MOD.read(td))

    def test_cli_rejects_malformed_ipv6_panel_url_and_abc_port_and_blank_token(self):
        """命令行遇到畸形 IPv6 --panel、非数字混排 listenHTTPS 及纯空白 --admin-token 均须优雅返回非零而非 Traceback。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cfg = td_path / 'config.yaml'
            portal_f = td_path / 'portal.json'
            meta_f = td_path / 'client_meta.json'
            portal_f.write_text(json.dumps({'api_key': 'k123456', 'port': 28888}), encoding='utf-8')
            meta_f.write_text(json.dumps({'server_name': 'node.example.com'}), encoding='utf-8')

            # 1) 混排非数字的 listenHTTPS: ":abc8443" 不得误抽出 8443
            cfg.write_text('masquerade:\n  listenHTTPS: ":abc8443"\n', encoding='utf-8')
            r1 = subprocess.run(
                [sys.executable, str(PANEL_JOIN), '--config', str(cfg),
                 '--portal', str(portal_f), '--meta', str(meta_f), '--format', 'json'],
                capture_output=True, text=True, encoding='utf-8', timeout=10,
            )
            self.assertEqual(r1.returncode, 3, f'期望返回 3，实际 {r1.returncode}: {r1.stdout} {r1.stderr}')

            # 2) 合法 listenHTTPS + 畸形 IPv6 --panel 必须返回 2 且无 Traceback
            cfg.write_text('masquerade:\n  listenHTTPS: ":8443"\n', encoding='utf-8')
            r2 = subprocess.run(
                [sys.executable, str(PANEL_JOIN), '--config', str(cfg),
                 '--portal', str(portal_f), '--meta', str(meta_f),
                 '--format', 'curl', '--panel', 'https://[::1'],
                capture_output=True, text=True, encoding='utf-8', timeout=10,
            )
            self.assertEqual(r2.returncode, 2, f'期望返回 2，实际 {r2.returncode}: {r2.stderr}')
            self.assertNotIn('Traceback', r2.stderr)

            # 3) --register 传纯空白 --admin-token 必须返回 2
            r3 = subprocess.run(
                [sys.executable, str(PANEL_JOIN), '--config', str(cfg),
                 '--portal', str(portal_f), '--meta', str(meta_f),
                 '--register', '--panel', 'https://mb.example.com', '--admin-token', '   '],
                capture_output=True, text=True, encoding='utf-8', timeout=10,
            )
            self.assertEqual(r3.returncode, 2, f'期望返回 2，实际 {r3.returncode}: {r3.stderr}')


if __name__ == '__main__':
    unittest.main()
