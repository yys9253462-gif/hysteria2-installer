"""证书到期时间用标准库解析，不依赖 GNU date 与 locale（2026-11-12 改）。

旧实现起 `date -d '<notAfter>' +%s` 子进程并钉 LC_ALL=C：zh_CN 下曾解析失败，busybox 等
非 GNU date 不认这个格式，证书卡片退化成「未知」。这里让 PATH 里只有 openssl 再取 cert_status。
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

OPENSSL = shutil.which('openssl')


@unittest.skipUnless(OPENSSL and os.name != 'nt', 'requires openssl on POSIX')
class CertExpiryParseTests(unittest.TestCase):
    def test_expiry_is_computed_without_a_date_binary(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'cert').mkdir()
            subprocess.run([OPENSSL, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                            '-nodes', '-keyout', str(td / 'cert' / 'server.key'), '-out', str(td / 'cert' / 'server.crt'),
                            '-days', '400', '-subj', '/CN=node.example.com'], check=True, capture_output=True)
            (td / 'config.yaml').write_text('listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n',
                                            encoding='utf-8')
            only_openssl = td / 'bin'
            only_openssl.mkdir()
            (only_openssl / 'openssl').symlink_to(OPENSSL)
            with mock.patch.dict(os.environ, {'PATH': str(only_openssl), 'LC_ALL': 'zh_CN.UTF-8'}):
                info = portal.cert_status(td, {'server_name': 'node.example.com'}, str(td / 'config.yaml'))
        self.assertIsNotNone(info['expires_at'], 'expiry not parsed without GNU date')
        self.assertAlmostEqual(info['expires_at'], time.time() + 400 * 86400, delta=2 * 86400)
        self.assertIn(info['expires_in_days'], (398, 399, 400))
        self.assertEqual(info['warn_level'], 'ok')


if __name__ == '__main__':
    unittest.main()
