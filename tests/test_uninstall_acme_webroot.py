"""完整卸载要删掉本工具建的 ACME webroot（2026-11-04 修）。

执行 uninstall_all 里真实的 Nginx 验证站点清理段（路径重定向到临时目录）。
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


@unittest.skipUnless(BASH, 'requires bash')
class UninstallAcmeWebrootTests(unittest.TestCase):
    def _run(self, extra_site):
        body = re.search(r'^uninstall_all\(\) \{\n.*?^\}', SRC, re.S | re.M).group(0)
        block = re.search(r'        local nginx_conf nginx_domain nginx_removed=0\n.*?\n        fi\n        if \[\[ "\$nginx_removed" == 1 \]\] && command -v nginx.*?\n        fi\n',
                          body, re.S).group(0)
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            conf = t / 'etc/nginx/conf.d'
            conf.mkdir(parents=True)
            web = t / 'var/lib/hy2-acme-webroot'
            (web / '.well-known').mkdir(parents=True)
            (conf / 'hy2-acme-a.example.conf').write_text(
                "# 由 hysteria2-installer 生成：只用于 Let's Encrypt 签发与续期 a.example\n"
                'server_name a.example;\nroot %s;\nreturn 404;\n' % '/var/lib/hy2-acme-webroot')
            if extra_site:
                (conf / 'mine.conf').write_text('root /var/lib/hy2-acme-webroot;\n')
            block = block.replace('/etc/nginx', str(t / 'etc/nginx')).replace(
                'rm -rf /var/lib/hy2-acme-webroot', 'rm -rf %s' % web)
            # grep 判定站点归属时比对的是字面 root 行，不能被替换
            block = block.replace("grep -qF 'root %s/var/lib" % t, "grep -qF 'root /var/lib")
            subprocess.run([BASH, '-c', 'HY2_DIR=%s\nnginx() { :; }\n%s' % (t, block)],
                           check=True, timeout=20)
            return web.exists()

    def test_webroot_removed_with_last_site(self):
        self.assertFalse(self._run(False))

    def test_webroot_kept_when_still_referenced(self):
        self.assertTrue(self._run(True))


if __name__ == '__main__':
    unittest.main()
