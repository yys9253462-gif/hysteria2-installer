"""install.sh 的 config_tls_cert 与门户同一规则读 tls.cert（2026-11-12 修）。

旧实现在 install.sh 里抄了四份 awk：`cert: /a.crt  # 注释` 读成带注释的路径，
sync_cert_meta 找不到证书、证书自愈的 path 单元盯错目录。执行真实函数与真实 sync_cert_meta。
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    m = re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M)
    return m.group(0) if m else ''


@unittest.skipUnless(BASH, 'requires bash')
class InstallConfigTlsCertTests(unittest.TestCase):
    def cert_of(self, tls_body):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\ntls:\n' + tls_body + 'auth:\n  type: http\n', encoding='utf-8')
            r = subprocess.run([BASH, '-c', fn('config_tls_cert') + '\nconfig_tls_cert "$1"', 'x', str(cfg)],
                               capture_output=True, text=True, timeout=20)
        return r.stdout.strip()

    def test_same_forms_as_the_portal_reader(self):
        cases = {
            '  cert: /etc/hysteria/server.crt\n  key: /k\n': '/etc/hysteria/server.crt',
            '  cert: "/etc/hysteria/server.crt"\n': '/etc/hysteria/server.crt',
            "  cert: '/etc/my certs/full.pem'\n": '/etc/my certs/full.pem',
            '  cert: /etc/hysteria/server.crt  # 由 Caddy 续期\n': '/etc/hysteria/server.crt',
            '  cert: "/etc/hysteria/server.crt" # quoted + comment\n': '/etc/hysteria/server.crt',
            '  key: /k\n  cert: /etc/hysteria/server.crt\n': '/etc/hysteria/server.crt',
            '# 段内顶格注释\n  cert: /etc/hysteria/server.crt\n': '/etc/hysteria/server.crt',
        }
        for body, want in cases.items():
            with self.subTest(body=body):
                self.assertEqual(self.cert_of(body), want)

    @unittest.skipUnless(shutil.which('openssl') and shutil.which('jq'), 'requires openssl and jq')
    def test_sync_cert_meta_heals_from_a_cert_line_with_a_trailing_comment(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / 'certs').mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                            '-nodes', '-keyout', str(t / 'certs' / 'key.pem'), '-out', str(t / 'certs' / 'full.pem'),
                            '-days', '30', '-subj', '/CN=node.example.com',
                            '-addext', 'subjectAltName=DNS:node.example.com'], check=True, capture_output=True)
            (t / 'config.yaml').write_text('listen: :443\ntls:\n  cert: %s/certs/full.pem  # 由 Caddy 续期\n'
                                           '  key: %s/certs/key.pem\n' % (t, t), encoding='utf-8')
            (t / 'client_meta.json').write_text(json.dumps({'cert_type': 'custom', 'server_name': 'old.example.com',
                                                            'is_insecure': False}), encoding='utf-8')
            script = '\n'.join(['HY2_DIR=%s' % t, 'HY2_CERT_DIR=%s/cert' % t, 'HY2_CONFIG=%s/config.yaml' % t,
                                'HY2_META_FILE=%s/client_meta.json' % t,
                                'log_info() { :; }', 'log_warn() { :; }', 'log_err() { :; }',
                                fn('config_tls_cert'), fn('sync_cert_meta'), 'sync_cert_meta; echo "RC=$?"'])
            r = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30)
            meta = json.loads((t / 'client_meta.json').read_text(encoding='utf-8'))
        self.assertIn('RC=0', r.stdout, r.stderr)
        self.assertEqual(meta['server_name'], 'node.example.com', 'meta was not healed from the configured cert')
        self.assertEqual(meta['cert_type'], 'self_signed')


if __name__ == '__main__':
    unittest.main()
