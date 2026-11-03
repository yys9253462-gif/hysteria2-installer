"""证书导入 / 扫描 / 复用都要拒绝过期证书与不配对的私钥，并认通配符（2026-11-04 修）。

用 openssl 现场签一套 CA + 叶证书，执行 install.sh 里真实的判定函数。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
OPENSSL = shutil.which('openssl')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


def sh(cmd, cwd):
    subprocess.run([BASH, '-c', cmd], cwd=cwd, check=True, capture_output=True, timeout=60)


@unittest.skipUnless(BASH and OPENSSL and __import__('os').name != 'nt', 'requires bash + openssl')
class CertPairCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        d = cls.d = Path(cls._td.name)
        sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj /CN=ca 2>/dev/null', d)
        for name, days, san in (('good', 30, 'DNS:hy2.example.com'), ('wild', 30, 'DNS:*.example.com')):
            sh('openssl req -newkey rsa:2048 -nodes -keyout %s.key -out %s.csr -subj /CN=%s 2>/dev/null && '
               'printf "subjectAltName=%s" > %s.ext && '
               'openssl x509 -req -in %s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days %d -extfile %s.ext -out %s.leaf 2>/dev/null && '
               'cat %s.leaf ca.crt > %s.full' % (name, name, name, san, name, name, days, name, name, name, name), d)
        # 一天内过期（-days 1 签出来的证书离到期不足 86400 秒），与已过期同样要拒
        sh('openssl req -newkey rsa:2048 -nodes -keyout old.key -out old.csr -subj /CN=old 2>/dev/null && '
           'printf "subjectAltName=DNS:hy2.example.com" > old.ext && '
           'openssl x509 -req -in old.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile old.ext -out old.leaf 2>/dev/null && '
           'cat old.leaf ca.crt > old.full', d)

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def check(self, call):
        script = '\n'.join([fn('pem_cert_count'), fn('_cert_key_usable'), fn('_accept_cert_pair'),
                            fn('_cert_matches_domain'), call + ' && echo YES || echo NO'])
        return subprocess.run([BASH, '-c', script], cwd=self.d, capture_output=True, text=True,
                              timeout=30).stdout.strip()

    def test_valid_pair_accepted(self):
        self.assertEqual(self.check('_accept_cert_pair good.full good.key'), 'YES')

    def test_expired_rejected(self):
        self.assertEqual(self.check('_accept_cert_pair old.full old.key'), 'NO')

    def test_mismatched_key_rejected(self):
        self.assertEqual(self.check('_cert_key_usable good.full wild.key'), 'NO')

    def test_wildcard_matches_one_label(self):
        self.assertEqual(self.check('_cert_matches_domain wild.full hy2.example.com'), 'YES')
        self.assertEqual(self.check('_cert_matches_domain wild.full a.b.example.com'), 'NO')
        self.assertEqual(self.check('_cert_matches_domain wild.full example.com'), 'NO')
        self.assertEqual(self.check('_cert_matches_domain good.full hy2.example.com'), 'YES')
        self.assertEqual(self.check('_cert_matches_domain good.full x.example.com'), 'NO')


if __name__ == '__main__':
    unittest.main()
