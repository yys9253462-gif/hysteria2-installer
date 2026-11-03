"""手动导入证书与 DNS 不一致提示（2026-11-04 修）。

* 证书绑定域名回车留空时，旧实现退回公网 IP 并标成可信证书：链接是 sni=<IP>、
  不带 insecure，客户端拿域名证书校验 IP 必然失败。现在必须是合法域名，否则回退自签。
* 无人值守时 read 读到 EOF：旧实现没有 `|| true`，set -e 让脚本在这里静默退出。
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


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


@unittest.skipUnless(BASH and shutil.which('openssl') and os.name != 'nt', 'requires a POSIX shell and openssl')
class CustomCertSniTests(unittest.TestCase):
    def run_setup(self, answers):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cert, key = td / 'fullchain.pem', td / 'privkey.pem'
            cert.write_text('-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n' * 2, encoding='utf-8')
            key.write_text('k', encoding='utf-8')
            feed = '2\n%s\n%s\n%s' % (bash_path(cert), bash_path(key), answers)
            script = '\n'.join([
                'set -eo pipefail', 'RED= GREEN= YELLOW= BLUE= CYAN= PLAIN=',
                'log_err() { echo "ERR $*"; }', 'log_warn() { :; }', 'log_info() { :; }', 'log_step() { :; }',
                'generate_self_signed_cert() { echo SELF_SIGNED; CERT_TYPE=self_signed; }',
                'reuse_existing_cert_config() { return 1; }',
                'PUBLIC_IP=203.0.113.7', 'HY2_CERT_DIR="%s"' % bash_path(td / 'c'),
                fn('pem_cert_count'), fn('is_valid_domain'), fn('setup_certificates'),
                'setup_certificates', 'echo "TYPE=${CERT_TYPE} SNI=${SERVER_NAME:-} RC=$?"'])
            return subprocess.run([BASH, '-c', script], input=feed, capture_output=True, text=True,
                                  encoding='utf-8', timeout=20).stdout

    def test_empty_sni_falls_back_to_self_signed_not_to_the_ip(self):
        out = self.run_setup('\n')
        self.assertIn('SELF_SIGNED', out)
        self.assertNotIn('SNI=203.0.113.7', out)

    def test_eof_at_the_sni_prompt_does_not_kill_the_install(self):
        out = self.run_setup('')
        self.assertIn('RC=0', out, out)

    def test_valid_domain_is_kept(self):
        out = self.run_setup('Node.Example.com\n')
        self.assertIn('TYPE=custom SNI=node.example.com', out)


if __name__ == '__main__':
    unittest.main()
