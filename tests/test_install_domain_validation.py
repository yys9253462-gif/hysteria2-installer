"""HY2_DOMAIN / HY2_EMAIL 与交互输入的域名、邮箱必须先校验（2026-11-03）。

这些值会原样进 config.yaml（双引号）、nginx `server_name ${domain};`、Caddyfile
站点块和 grep 正则。旧校验只挡 / 与 :（邮箱只要求含 @），引号、分号、花括号、
空格、换行都能进去，写坏或注入配置后 Hysteria / nginx / Caddy 反复重启。
"""
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
SOURCE = INSTALL.read_text(encoding='utf-8')


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    if not match:
        raise AssertionError(name)
    return match.group(0)


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class DomainValidationTests(unittest.TestCase):
    def check(self, fn, value):
        script = function('is_valid_domain') + '\n' + function('is_valid_email') + '\n' + fn + ' "$1"'
        return subprocess.run(['bash', '-c', script, 'x', value], capture_output=True,
                              timeout=10).returncode == 0

    def test_domains(self):
        for good in ('hy2.example.com', 'a.b', 'x-1.example.co.uk', 'node1.zy3a.com'):
            self.assertTrue(self.check('is_valid_domain', good), good)
        for bad in ('', 'example', 'evil.com"; touch /tmp/x', 'a.com;', 'a.com }', 'a .com',
                    'a.com\nlisten: :1', '-a.com', 'a-.com', 'https://a.com', 'a.com:443',
                    'a..com', 'a' * 64 + '.com'):
            self.assertFalse(self.check('is_valid_domain', bad), repr(bad))

    def test_emails(self):
        for good in ('me@example.com', 'ops+acme@sub.example.org'):
            self.assertTrue(self.check('is_valid_email', good), good)
        for bad in ('', '@', 'me@', 'me@example', 'a b@example.com', 'me@example.com"\n',
                    'me@ex@ample.com', 'me@example.com; rm'):
            self.assertFalse(self.check('is_valid_email', bad), repr(bad))

    def test_noninteractive_env_is_rejected_before_any_work(self):
        """免交互的坏值在动工前就退出，并说明是哪个变量（与 CI 里 HY2_PORT 的检查同一层）。"""
        for env, needle in (({'HY2_CERT_TYPE': '3', 'HY2_DOMAIN': 'evil.com";x'}, 'HY2_DOMAIN'),
                            ({'HY2_CERT_TYPE': '3', 'HY2_DOMAIN': 'ok.example.com',
                              'HY2_EMAIL': 'bad email@x.com'}, 'HY2_EMAIL')):
            with self.subTest(env=env):
                result = subprocess.run(['bash', str(INSTALL), 'install'], capture_output=True,
                                        text=True, timeout=30, env=dict(os.environ, **env),
                                        stdin=subprocess.DEVNULL)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(needle, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
