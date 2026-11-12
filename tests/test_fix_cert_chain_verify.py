"""fix_cert_chain.sh 修复后自检用的端口与 SNI（2026-11-12 修）。

旧实现：端口只去掉开头一个冒号，`0.0.0.0:8443` / `":8443"` 原样拿去连；
SNI 从 -subject 整行截 CN 之后的全部内容，CN 后面还有字段或证书不带 CN 时都取错。
两种情况都会把一次成功的修复报成「验证未通过」。这里摘出真实函数执行。
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'fix_cert_chain.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
BASH = shutil.which('bash')
OPENSSL = shutil.which('openssl')


def _func(name):
    start = SRC.index(name + ' () {')
    return SRC[start:SRC.index('\n}\n', start) + 3]


def run(script):
    return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30)


@unittest.skipUnless(BASH, 'requires bash')
class MasqueradePortTests(unittest.TestCase):
    def port_of(self, masquerade_body):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\nmasquerade:\n  type: proxy\n' + masquerade_body, encoding='utf-8')
            r = run(_func('masq_https_port') + 'masq_https_port %s\n' % cfg)
        return r.stdout.strip()

    def test_forms_written_by_installer_and_by_hand(self):
        cases = {
            '  listenHTTPS: :8443\n': '8443',
            '  listenHTTPS: 0.0.0.0:8443\n': '8443',
            '  listenHTTPS: ":8443"\n': '8443',
            "  listenHTTPS: '[::]:9443'\n": '9443',
            '  listenHTTPS: :8443  # 订阅端口\n': '8443',
        }
        for body, want in cases.items():
            with self.subTest(body=body):
                self.assertEqual(self.port_of(body), want)

    def test_commented_line_is_skipped(self):
        self.assertEqual(self.port_of('  # listenHTTPS: :1111\n  listenHTTPS: :2222\n'), '2222')

    def test_out_of_range_values_are_not_returned(self):
        for body in ('  listenHTTPS: :0\n', '  listenHTTPS: :70000\n', '  listenHTTPS: :\n'):
            with self.subTest(body=body):
                self.assertEqual(self.port_of(body), '')


@unittest.skipUnless(BASH, 'requires bash')
class RestartAfterRepairTests(unittest.TestCase):
    """重启前先 reset-failed（2026-11-12 修）：撞上 StartLimitBurst 的服务直接 restart 会被拒绝，
    修好的链被当成「起不来」回滚。systemctl 打桩：没先 reset-failed 就拒绝启动。"""

    STUB = ('systemctl() { echo "$*" >> "$LOG"; case "$1" in reset-failed) : > "$CLEARED";; '
            'restart) [ -f "$CLEARED" ] || return 1; echo started > "$STATE";; esac; }\n')

    def test_restart_clears_the_start_limit_first(self):
        with tempfile.TemporaryDirectory() as td:
            env = 'LOG=%s/log CLEARED=%s/cleared STATE=%s/state\n' % (td, td, td)
            r = run(env + self.STUB + _func('restart_hysteria') + 'restart_hysteria\ncat %s/state\n' % td)
        self.assertIn('started', r.stdout, 'restart refused: reset-failed was not issued first')

    def test_both_restarts_in_the_repair_path_use_it(self):
        body = SRC[SRC.index('if [[ "$CHANGED" == "1" ]]; then'):SRC.index('SUB_PORT="$(masq_https_port')]
        self.assertEqual(body.count('restart_hysteria'), 2)
        self.assertNotIn('systemctl restart hysteria-server', body)


@unittest.skipUnless(BASH and OPENSSL, 'requires bash and openssl')
class CertSniTests(unittest.TestCase):
    def sni_of(self, subject, san=None):
        with tempfile.TemporaryDirectory() as td:
            key, cert = Path(td) / 'k.pem', Path(td) / 'c.pem'
            cmd = [OPENSSL, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                   '-nodes', '-days', '1', '-subj', subject, '-keyout', str(key), '-out', str(cert)]
            if san:
                cmd += ['-addext', 'subjectAltName=' + san]
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            r = run(_func('cert_sni') + 'cert_sni %s\n' % cert)
        return r.stdout.strip()

    def test_certificate_without_cn_uses_san(self):
        self.assertEqual(self.sni_of('/O=Example Org', 'DNS:node.example.com'), 'node.example.com')

    def test_cn_followed_by_other_fields_is_cut_cleanly(self):
        self.assertEqual(self.sni_of('/CN=a.example.com/O=Example Org'), 'a.example.com')

    def test_wildcard_san_becomes_a_matching_hostname(self):
        self.assertEqual(self.sni_of('/CN=example.com', 'DNS:*.example.com,DNS:example.com'), 'www.example.com')


if __name__ == '__main__':
    unittest.main()
