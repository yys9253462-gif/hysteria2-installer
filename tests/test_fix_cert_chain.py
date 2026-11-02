"""fix_cert_chain.sh 必须读懂 install.sh 写出的带引号 tls.cert（2026-11-03）。

install.sh 写的是 `cert: "${CERT_FILE}"`。旧的 cert_of 原样保留引号，
拿 "\"/path\"" 去找文件，在每台由安装脚本生成配置的节点上都报「证书文件不存在」。
这里只跑 --dry-run：不改配置、不重启任何服务。
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'fix_cert_chain.sh'
PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class FixCertChainPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.leaf = self.root / 'node.example.com.cer'
        self.leaf.write_text(PEM, encoding='utf-8')
        self.full = self.root / 'fullchain.cer'
        self.full.write_text(PEM * 2, encoding='utf-8')

    def dry_run(self, cert_line):
        config = self.root / 'config.yaml'
        config.write_text('listen: :443\ntls:\n  %s\n  key: "%s/node.key"\n\n'
                          'masquerade:\n  listenHTTPS: :8443\n' % (cert_line, self.root),
                          encoding='utf-8')
        result = subprocess.run(['bash', str(SCRIPT), '--dry-run', '--config', str(config)],
                                capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout + result.stderr

    def assert_finds_fullchain(self, cert_line):
        code, out = self.dry_run(cert_line)
        self.assertEqual(code, 0, out)
        self.assertNotIn('证书文件不存在', out)
        self.assertIn('找到完整链文件：%s' % self.full, out)

    def test_double_quoted_path_from_installer(self):
        self.assert_finds_fullchain('cert: "%s"' % self.leaf)

    def test_single_quoted_path(self):
        self.assert_finds_fullchain("cert: '%s'" % self.leaf)

    def test_unquoted_path_with_trailing_comment(self):
        self.assert_finds_fullchain('cert: %s   # leaf only' % self.leaf)

    def test_full_chain_needs_no_change(self):
        code, out = self.dry_run('cert: "%s"' % self.full)
        self.assertEqual(code, 0, out)
        self.assertIn('已包含完整链', out)


if __name__ == '__main__':
    unittest.main()
