"""手动导入证书时的证书链自检（2026-11-03 修）。

旧写法 `$(grep -c 'BEGIN CERTIFICATE' f || echo 0)` 在文件里没有证书时得到
"0\n0"，`[[ … -lt 2 ]]` 算术报错判假：不含证书的文件跳过「仅叶证书」的补链
检查，被直接当成证书使用。这里执行 setup_certificates 里那条判断本身。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


def chain_check_line():
    m = re.search(r'# 证书链自检.*?\n\s*local chain_ok=1 sibling\n\s*(if \[\[.*?\]\]); then\n', SRC, re.S)
    return m.group(1)


def helpers():
    m = re.search(r'^pem_cert_count\(\) \{\n.*?^\}', SRC, re.S | re.M)
    return m.group(0) if m else ''


@unittest.skipUnless(BASH, 'requires bash')
class CertChainCountTests(unittest.TestCase):
    def needs_chain(self, content):
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / 'cert.pem'
            cert.write_text(content, encoding='utf-8')
            script = '%s\ninput_cert="%s"\n%s; then echo SHORT; else echo FULL; fi\n' % (
                helpers(), bash_path(cert), chain_check_line())
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                  timeout=20).stdout.strip()

    def test_file_without_certificate_is_not_taken_as_full_chain(self):
        self.assertEqual(self.needs_chain('not a certificate\n'), 'SHORT')

    def test_leaf_only_and_full_chain(self):
        block = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
        self.assertEqual(self.needs_chain(block), 'SHORT')
        self.assertEqual(self.needs_chain(block * 2), 'FULL')


if __name__ == '__main__':
    unittest.main()
