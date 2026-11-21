"""回归测试：panel-join.py 拦截非法面板端口、控制字符以及含换行符的管理员令牌。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'panel-join.py'


class PanelJoinHardeningTests(unittest.TestCase):
    def _fixture(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        cfg = root / 'config.yaml'
        portal_json = root / 'portal.json'
        meta = root / 'client_meta.json'
        cfg.write_text('listen: :443\nmasquerade:\n  listenHTTPS: :8443\n', encoding='utf-8')
        portal_json.write_text(json.dumps({'api_key': 'fake-key-test-only', 'port': 18080}), encoding='utf-8')
        meta.write_text(json.dumps({'server_name': 'node.example.com', 'public_ip': '198.51.100.1', 'is_insecure': False}), encoding='utf-8')
        return cfg, portal_json, meta

    def test_invalid_panel_port_or_control_chars_rejected_as_exit_2(self):
        cfg, portal_json, meta = self._fixture()
        for bad_panel in (
            'https://panel.example.com:abc',
            'https://panel.example.com:70000',
            'https://panel.example.com:0',
            'https://panel.example.com/a\nb',
        ):
            r = subprocess.run(
                [sys.executable, str(SCRIPT), '--config', str(cfg), '--portal', str(portal_json),
                 '--meta', str(meta), '--format', 'curl', '--panel', bad_panel],
                capture_output=True, text=True, encoding='utf-8',
            )
            self.assertEqual(r.returncode, 2, f'panel={bad_panel!r} stdout={r.stdout!r} stderr={r.stderr!r}')

    def test_admin_token_with_newline_rejected_before_network(self):
        cfg, portal_json, meta = self._fixture()
        r = subprocess.run(
            [sys.executable, str(SCRIPT), '--config', str(cfg), '--portal', str(portal_json),
             '--meta', str(meta), '--register', '--panel', 'https://panel.example.com',
             '--admin-token', 'token-part1\r\nX-Injected: 1'],
            capture_output=True, text=True, encoding='utf-8',
        )
        self.assertEqual(r.returncode, 2, f'stdout={r.stdout!r} stderr={r.stderr!r}')
        self.assertIn('admin-token', r.stderr)


if __name__ == '__main__':
    unittest.main()
