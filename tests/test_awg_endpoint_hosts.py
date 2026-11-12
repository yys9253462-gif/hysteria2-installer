"""AWG 连接地址必须真是主机（2026-11-04 修）。

旧规则只验字符集：「...」「-」「[:]」「[1.2.3.4]」都能通过，写进客户端配置
`Endpoint = ...:51820` 后永远握不上手，管理员却看到成功。门户与 awgctl 两侧都要验。
"""
import ast
import copy
import ipaddress
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
AWGCTL = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')

BAD = ('...', '-', '_', '[.]', '[:]', '[1.2.3.4]', 'a..b', '-host.example.com',
       # 末段全是数字却不是 IPv4（2026-11-12 修）：顶级域不会全是数字，客户端当域名解析必然失败。
       '999.1.1.1', '1.2.3', '12345', '1.2.3.4.5', '01.2.3.4', '300.1.1.1:51820')
GOOD = ('vpn.example.com', 'vpn.example.com:51820', '1.2.3.4', '[2001:db8::1]', '[2001:db8::1]:51820',
        '10.0.0.1:51820', 'vpn')


def portal_checker():
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == 'awg_endpoint_error')
    regex = next(n for n in ast.walk(TREE) if isinstance(n, ast.Assign)
                 and any(getattr(t, 'id', '') == 'VALID_AWG_ENDPOINT_RE' for t in n.targets))
    env = {'re': re, 'ipaddress': ipaddress}
    exec(compile(ast.Module(body=[copy.deepcopy(regex), copy.deepcopy(fn)], type_ignores=[]),
                 '<awg-endpoint>', 'exec'), env)
    return env['awg_endpoint_error']


class AwgEndpointHostTests(unittest.TestCase):
    def test_portal_rejects_non_hosts(self):
        check = portal_checker()
        for ep in BAD:
            with self.subTest(ep=ep):
                self.assertTrue(check(ep), '门户放过了 %r' % ep)
        for ep in GOOD:
            with self.subTest(ep=ep):
                self.assertEqual(check(ep), '', ep)

    @unittest.skipUnless(BASH and shutil.which('python3'), 'requires bash and python3')
    def test_awgctl_rejects_non_hosts(self):
        fn = re.search(r'^validate_endpoint\(\) \{\n.*?^\}', AWGCTL, re.S | re.M).group(0)
        for ep, want in [(e, 'BAD') for e in BAD] + [(e, 'OK') for e in GOOD]:
            with self.subTest(ep=ep):
                script = 'log_err() { :; }\n%s\nvalidate_endpoint "$1" && echo OK || echo BAD' % fn
                out = subprocess.run([BASH, '-c', script, '_', ep], capture_output=True, text=True,
                                     timeout=20).stdout.strip()
                self.assertEqual(out, want)


if __name__ == '__main__':
    unittest.main()
