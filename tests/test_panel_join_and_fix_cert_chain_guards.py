"""回归测试：panel-join.py 非 IPv6 含冒号主机拦截、masquerade 段限定与 api_key/name 校验，以及 fix_cert_chain.sh PEM 头精确计数与陷阱清理。"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL_JOIN_PATH = ROOT / 'panel-join.py'
FIX_CERT_SRC = (ROOT / 'fix_cert_chain.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _load_panel_join():
    spec = importlib.util.spec_from_file_location('panel_join_t55', PANEL_JOIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


BASH = _find_bash()


class PanelJoinAndFixCertChainGuardsTests(unittest.TestCase):
    def test_panel_join_safe_host_rejects_non_ipv6_colon_and_accepts_ipv6(self):
        """_safe_host 须拒绝 'host:8443' 等含冒号非 IPv6 脏主机，且规范化合法 IPv6。"""
        pj = _load_panel_join()
        self.assertEqual(pj._safe_host('node.example.com:8443'), '')
        self.assertEqual(pj._safe_host(':::garbage'), '')
        self.assertEqual(pj._safe_host('2001:db8::1'), '2001:db8::1')
        self.assertEqual(pj._safe_host('[2001:db8::1]'), '2001:db8::1')
        self.assertEqual(pj._safe_host('node.example.com'), 'node.example.com')

    def test_panel_join_does_not_grab_listen_https_outside_masquerade_and_rejects_whitespace_api_key(self):
        """panel-join.py 不得跨段抓取非 masquerade 的 listenHTTPS，且拒绝含空格 api_key 与含换行 --name。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'config.yaml'
            portal_f = root / 'portal.json'
            meta_f = root / 'client_meta.json'
            # masquerade 段无 listenHTTPS，但 other 段有 listenHTTPS
            cfg.write_text('listen: :443\nother:\n  listenHTTPS: :9999\nmasquerade:\n  type: proxy\n', encoding='utf-8')
            portal_f.write_text(json.dumps({'api_key': 'goodkey', 'port': 18080}), encoding='utf-8')
            meta_f.write_text(json.dumps({'server_name': 'node.example.com', 'is_insecure': False}), encoding='utf-8')

            proc = subprocess.run(
                ['python3' if shutil.which('python3') else 'python', str(PANEL_JOIN_PATH),
                 '--config', str(cfg), '--portal', str(portal_f), '--meta', str(meta_f)],
                capture_output=True, text=True, encoding='utf-8', timeout=15,
            )
            self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)

            # 含空白 api_key 必须返回 2
            cfg.write_text('listen: :443\nmasquerade:\n  type: proxy\n  listenHTTPS: :8443\n', encoding='utf-8')
            portal_f.write_text(json.dumps({'api_key': 'bad key with space', 'port': 18080}), encoding='utf-8')
            proc2 = subprocess.run(
                ['python3' if shutil.which('python3') else 'python', str(PANEL_JOIN_PATH),
                 '--config', str(cfg), '--portal', str(portal_f), '--meta', str(meta_f)],
                capture_output=True, text=True, encoding='utf-8', timeout=15,
            )
            self.assertEqual(proc2.returncode, 2, proc2.stdout + proc2.stderr)

            # --name 含换行时必须返回 2
            portal_f.write_text(json.dumps({'api_key': 'goodkey', 'port': 18080}), encoding='utf-8')
            proc3 = subprocess.run(
                ['python3' if shutil.which('python3') else 'python', str(PANEL_JOIN_PATH),
                 '--config', str(cfg), '--portal', str(portal_f), '--meta', str(meta_f),
                 '--format', 'curl', '--panel', 'https://panel.example.com', '--name', 'bad\nname'],
                capture_output=True, text=True, encoding='utf-8', timeout=15,
            )
            self.assertEqual(proc3.returncode, 2, proc3.stdout + proc3.stderr)

    @unittest.skipUnless(BASH, 'requires bash')
    def test_fix_cert_chain_exact_pem_count_and_return_trap(self):
        """fix_cert_chain.sh 的 n_certs 须精确匹配 -----BEGIN CERTIFICATE-----，不把 CSR 误算为证书；set_tls_cert 须有 RETURN 清理。"""
        self.assertIn('-----BEGIN CERTIFICATE-----', FIX_CERT_SRC)
        m = re.search(r'^set_tls_cert\s*\(\)\s*\{.*?^\}', FIX_CERT_SRC, re.M | re.S)
        self.assertIsNotNone(m)
        self.assertIn('trap - RETURN;', m.group(0))
        with tempfile.TemporaryDirectory() as td:
            csr = Path(td) / 'req.pem'
            csr.write_text(
                '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n'
                '-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n',
                encoding='utf-8',
            )
            n_certs_line = next(l for l in FIX_CERT_SRC.splitlines() if l.startswith('n_certs ()'))
            script = f'{n_certs_line}\nn_certs "{csr.as_posix()}"\n'
            proc = subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), '1')


if __name__ == '__main__':
    unittest.main()
