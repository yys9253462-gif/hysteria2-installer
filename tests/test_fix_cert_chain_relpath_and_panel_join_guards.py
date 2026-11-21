"""回归测试：fix_cert_chain.sh 相对 tls.cert 路径解析与临时文件清理；panel-join.py ASCII 端口校验、api_key 控制字符及内嵌凭据面板 URL 拦截。"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX_CERT = ROOT / 'fix_cert_chain.sh'
PANEL_JOIN = ROOT / 'panel-join.py'


class FixCertChainRelpathAndPanelJoinGuardsTests(unittest.TestCase):
    def test_fix_cert_chain_resolves_relative_tls_cert_and_cleans_tmp_on_mv_failure(self):
        """相对路径 tls.cert 在任意工作目录执行 --dry-run 应能按 config 所在目录定位，且 mv 失败清理临时文件。"""
        src = FIX_CERT.read_text(encoding='utf-8').replace('\r\n', '\n')
        self.assertIn('mv -f "$tmp" "$1" || { rm -f "$tmp"; return 1; }', src)
        self.assertIn('mv -f "$tmp" "$2" || { rm -f "$tmp"; return 1; }', src)
        self.assertIn('CERT_FILE="$(dirname "$CONFIG")/${CERT_FILE}"', src)

        bash_exe = shutil.which('bash')
        if os.name == 'nt' and Path(r'C:\Program Files\Git\bin\bash.exe').exists():
            bash_exe = r'C:\Program Files\Git\bin\bash.exe'
        if not bash_exe:
            self.skipTest('当前环境无可用 bash')

        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as other_cwd:
            td_path = Path(td)
            (td_path / 'cert').mkdir()
            # 含两张证书的完整链，--dry-run 应识别成功返回 0
            (td_path / 'cert' / 'fullchain.pem').write_text(
                '-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n'
                '-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n',
                encoding='utf-8',
            )
            cfg = td_path / 'config.yaml'
            cfg.write_text('tls:\n  cert: "cert/fullchain.pem"\n  key: "cert/server.key"\n', encoding='utf-8')
            res = subprocess.run(
                [bash_exe, FIX_CERT.as_posix(), '--dry-run', '--config', cfg.as_posix()],
                cwd=other_cwd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('已包含完整链', res.stdout)

    def test_panel_join_rejects_unicode_ports_control_api_key_and_userinfo_panel_url(self):
        """panel-join.py 必须拦截全角端口数字、含控制字符的 api_key 及带 user:pass@ 的 --panel 地址。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cfg = td_path / 'config.yaml'
            portal_file = td_path / 'portal.json'
            meta_file = td_path / 'client_meta.json'
            meta_file.write_text(json.dumps({'server_name': 'node.example.com', 'is_insecure': False}), encoding='utf-8')

            # 1) 全角数字 listenHTTPS 不应被识别成有效端口
            cfg.write_text('listen: :443\nmasquerade:\n  listenHTTPS: :８４４３\n', encoding='utf-8')
            portal_file.write_text(json.dumps({'api_key': 'k' * 24, 'port': '８０８０'}), encoding='utf-8')
            res1 = subprocess.run(
                [sys.executable, str(PANEL_JOIN), '--config', str(cfg), '--portal', str(portal_file), '--meta', str(meta_file)],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
            )
            self.assertEqual(res1.returncode, 3, res1.stdout + res1.stderr)

            # 2) 含控制字符的 api_key 必须返回 2 拒绝
            cfg.write_text('listen: :443\nmasquerade:\n  listenHTTPS: :8443\n', encoding='utf-8')
            portal_file.write_text(json.dumps({'api_key': 'bad\nkey', 'port': 18080}), encoding='utf-8')
            res2 = subprocess.run(
                [sys.executable, str(PANEL_JOIN), '--config', str(cfg), '--portal', str(portal_file), '--meta', str(meta_file)],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
            )
            self.assertEqual(res2.returncode, 2, res2.stdout + res2.stderr)

            # 3) --panel 带 user:pass@ 必须返回 2 拒绝
            portal_file.write_text(json.dumps({'api_key': 'k' * 24, 'port': 18080}), encoding='utf-8')
            res3 = subprocess.run(
                [sys.executable, str(PANEL_JOIN), '--config', str(cfg), '--portal', str(portal_file),
                 '--meta', str(meta_file), '--format', 'curl', '--panel', 'https://u:p@panel.example.com'],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
            )
            self.assertEqual(res3.returncode, 2, res3.stdout + res3.stderr)


if __name__ == '__main__':
    unittest.main()
