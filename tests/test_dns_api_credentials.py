"""DNS API 签发把凭据通过环境变量交给 acme.sh（2026-11-04 修）。

旧实现传 --dns_cf_token 等参数，acme.sh 报 Unknown parameter 退出；DuckDNS 还用错了
插件名（dns_dp 是 DNSPod）。执行真实的 setup_cert_via_dns_api，acme.sh 打桩记录调用。
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


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class DnsApiCredentialsTests(unittest.TestCase):
    def run_issue(self, env_lines):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / '.acme.sh').mkdir()
            stub = home / '.acme.sh' / 'acme.sh'
            stub.write_text('#!/bin/bash\n'
                            '[[ "$1" == --issue ]] && { printf "ARGS %s\\n" "$*"; '
                            'printf "ENV CF_Token=%s CF_Email=%s CF_Key=%s Ali_Key=%s Ali_Secret=%s DuckDNS_Token=%s\\n" '
                            '"$CF_Token" "$CF_Email" "$CF_Key" "$Ali_Key" "$Ali_Secret" "$DuckDNS_Token"; } >> "$HOME/calls"\n'
                            'exit 1\n')
            stub.chmod(0o755)
            script = '\n'.join(['HOME=%s' % home, 'log_info() { :; }', 'log_warn() { :; }',
                                'log_err() { :; }', 'hy2_acme_ensure() { :; }'] + env_lines
                               + [fn('setup_cert_via_dns_api'), 'setup_cert_via_dns_api a.example.com 3>/dev/null'])
            subprocess.run([BASH, '-c', script], capture_output=True, timeout=20)
            calls = home / 'calls'
            return calls.read_text() if calls.exists() else ''

    def test_cloudflare_token_goes_through_env(self):
        out = self.run_issue(['HY2_CF_TOKEN=tok', 'HY2_CF_EMAIL=me@x'])
        self.assertIn('--dns dns_cf', out)
        self.assertNotIn('--dns_cf_token', out)
        self.assertIn('CF_Token=tok CF_Email=me@x', out)

    def test_duckdns_uses_its_own_plugin(self):
        out = self.run_issue(['HY2_DP_TOKEN=duck'])
        self.assertIn('--dns dns_duckdns', out)
        self.assertIn('DuckDNS_Token=duck', out)

    def test_alicloud_key_goes_through_env(self):
        out = self.run_issue(['HY2_ALICLOUD_KEY=ak', 'HY2_ALICLOUD_SECRET=sk'])
        self.assertIn('Ali_Key=ak', out)
        self.assertIn('Ali_Secret=sk', out)
        self.assertNotIn('--dns_ali_key', out)

    # 2026-11-12 修：Cloudflare API Token 不需要邮箱；Global API Key 走 CF_Key；阿里云缺 Secret 不去签发。
    def test_cloudflare_api_token_alone_is_enough(self):
        out = self.run_issue(['HY2_CF_TOKEN=tok'])
        self.assertIn('--dns dns_cf', out)
        self.assertIn('CF_Token=tok', out)

    def test_cloudflare_global_key_is_sent_as_cf_key(self):
        out = self.run_issue(['HY2_CF_KEY=gk', 'HY2_CF_EMAIL=me@x'])
        self.assertIn('--dns dns_cf', out)
        self.assertIn('CF_Token= CF_Email=me@x CF_Key=gk', out)

    def test_alicloud_without_secret_is_refused_before_issuing(self):
        self.assertEqual(self.run_issue(['HY2_ALICLOUD_KEY=ak']), '')


if __name__ == '__main__':
    unittest.main()
