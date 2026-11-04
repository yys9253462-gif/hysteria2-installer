"""重新配置时沿用现有自签证书，pin 不变（2026-11-04 修）。

执行 install.sh 里真实的 generate_self_signed_cert 两次，比较证书指纹。
"""
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


@unittest.skipUnless(BASH and shutil.which('openssl') and os.name != 'nt', 'requires bash + openssl')
class SelfSignedReuseTests(unittest.TestCase):
    def gen(self, d, regen=''):
        script = '\n'.join(['HY2_CERT_DIR=%s' % d, 'log_step() { :; }', 'log_info() { :; }',
                            'HY2_REGEN_SELF_SIGNED=%s' % regen, fn('_cert_key_usable'),
                            fn('generate_self_signed_cert'), 'generate_self_signed_cert',
                            'openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256'])
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30).stdout.strip()

    def test_second_run_keeps_the_same_certificate(self):
        with tempfile.TemporaryDirectory() as d:
            first = self.gen(d)
            self.assertIn('Fingerprint', first)
            self.assertEqual(self.gen(d), first)

    def test_explicit_regen_makes_a_new_one(self):
        with tempfile.TemporaryDirectory() as d:
            first = self.gen(d)
            self.assertNotEqual(self.gen(d, regen='1'), first)


if __name__ == '__main__':
    unittest.main()
