"""卸载要撤掉安装器登记的 acme.sh 续期（2026-11-03 修）。

签发时 --install-cert 把证书写进 /etc/hysteria/cert/acme-<域名>.crt 并登记 reloadcmd；
旧卸载不撤，acme.sh 的 cron 之后照样续期（Nginx 方式每次报错，DNS API 方式又把
/etc/hysteria/cert 建回来）。SE 上用 acme.sh 3.1.1 确认：--remove 让域名离开续期
列表、退出码 0；对不存在的域名返回非零但无副作用。这里执行卸载里那一段。
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


def snippet():
    m = re.search(r'\n(        # 撤掉安装器登记的 acme\.sh 续期.*?\n        fi\n)', SRC, re.S)
    return m.group(1)


def is_valid_domain():
    return re.search(r'^is_valid_domain\(\) \{\n.*?^\}', SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class UninstallAcmeRenewalTests(unittest.TestCase):
    def test_installer_certificates_are_removed_from_renewal(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            home, certs = td / 'home', td / 'cert'
            (home / '.acme.sh').mkdir(parents=True)
            certs.mkdir()
            log = td / 'calls'
            acme = home / '.acme.sh' / 'acme.sh'
            acme.write_text('#!/bin/sh\necho "$*" >> "%s"\n' % bash_path(log), encoding='utf-8')
            acme.chmod(0o755)
            for name in ('acme-node.example.com.crt', 'server.crt', 'acme-bad;name.crt'):
                (certs / name).write_text('x', encoding='utf-8')
            script = '\n'.join([is_valid_domain(), 'HOME="%s"' % bash_path(home),
                                'HY2_CERT_DIR="%s"' % bash_path(certs), 'f() {', snippet(), '}', 'f'])
            subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20)
            calls = log.read_text(encoding='utf-8').splitlines() if log.exists() else []
            self.assertEqual(calls, ['--remove -d node.example.com --ecc'])


if __name__ == '__main__':
    unittest.main()
