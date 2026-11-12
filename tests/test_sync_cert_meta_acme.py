"""内置 ACME 节点上 sync_cert_meta 不拿残留的旧自签证书「自愈」（2026-11-06 修）。

自签改成 ACME 后 cert/server.crt 还在；旧实现在 config.yaml 没有 tls.cert 时退回它，
把 client_meta.json 改成 self_signed / www.bing.com / insecure，订阅随即握手失败。
执行 install.sh 里真实的 sync_cert_meta，用 openssl 现场生成那张旧自签证书。
"""
import json
import os
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
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH and shutil.which('openssl') and shutil.which('jq') and os.name != 'nt',
                     'requires bash, openssl and jq')
class SyncCertMetaAcmeTests(unittest.TestCase):
    def test_acme_node_meta_is_not_rewritten_from_stale_self_signed(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / 'cert').mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                            '-nodes', '-keyout', str(t / 'cert' / 'server.key'), '-out', str(t / 'cert' / 'server.crt'),
                            '-days', '30', '-subj', '/CN=www.bing.com'], check=True, capture_output=True)
            (t / 'config.yaml').write_text('listen: :443\nacme:\n  domains:\n    - node.example.com\n'
                                           '  email: a@example.com\n  type: http\n')
            meta = {'cert_type': 'acme', 'server_name': 'node.example.com', 'is_insecure': False}
            (t / 'client_meta.json').write_text(json.dumps(meta))
            script = '\n'.join(['HY2_DIR=%s' % t, 'HY2_CERT_DIR=%s/cert' % t, 'HY2_CONFIG=%s/config.yaml' % t,
                                'HY2_META_FILE=%s/client_meta.json' % t,
                                'log_info() { :; }', 'log_warn() { :; }', 'log_step() { :; }',
                                fn('config_tls_cert'), fn('sync_cert_meta'), 'sync_cert_meta; echo "RC=$?"'])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30)
            after = json.loads((t / 'client_meta.json').read_text())
        self.assertEqual(after['cert_type'], 'acme', out.stdout + out.stderr)
        self.assertEqual(after['server_name'], 'node.example.com')
        self.assertFalse(after['is_insecure'])


if __name__ == '__main__':
    unittest.main()
