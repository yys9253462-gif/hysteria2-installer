"""门户读取 config.yaml 的 tls.cert：引号、行尾注释、cert / key 顺序（2026-11-12 修）。

旧实现只剥首尾引号：`cert: /a.crt  # 注释` 读成带注释的路径（fix_cert_chain.sh 认这种写法，
门户却找不到证书）；读到 key: 就停，key 写在 cert 前面时取不到。证书状态、pin 与自愈都靠它。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ConfigTlsCertPathTests(unittest.TestCase):
    def cert_of(self, tls_body):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\ntls:\n' + tls_body + 'auth:\n  type: http\n', encoding='utf-8')
            return portal._config_tls_cert_path(str(cfg))

    def test_written_forms(self):
        cases = {
            '  cert: /etc/hysteria/server.crt\n  key: /etc/hysteria/server.key\n': '/etc/hysteria/server.crt',
            '  cert: "/etc/hysteria/server.crt"\n  key: "/k"\n': '/etc/hysteria/server.crt',
            "  cert: '/etc/my certs/full.pem'\n": '/etc/my certs/full.pem',
            '  cert: /etc/hysteria/server.crt  # 由 Caddy 续期\n': '/etc/hysteria/server.crt',
            '  cert: "/etc/hysteria/server.crt" # quoted + comment\n': '/etc/hysteria/server.crt',
        }
        for body, want in cases.items():
            with self.subTest(body=body):
                self.assertEqual(self.cert_of(body), want)

    def test_key_before_cert_is_still_found(self):
        self.assertEqual(self.cert_of('  key: /etc/hysteria/server.key\n  cert: /etc/hysteria/server.crt\n'),
                         '/etc/hysteria/server.crt')

    def test_commented_out_cert_and_other_sections_are_ignored(self):
        self.assertEqual(self.cert_of('  # cert: /old.crt\n  cert: /new.crt\n'), '/new.crt')
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('masquerade:\n  cert: /not-tls.crt\ntls:\n  key: /k\n', encoding='utf-8')
            self.assertEqual(portal._config_tls_cert_path(str(cfg)), '')


if __name__ == '__main__':
    unittest.main()
