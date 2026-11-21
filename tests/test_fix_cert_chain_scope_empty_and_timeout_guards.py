import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX_CERT = REPO / 'fix_cert_chain.sh'
SRC = FIX_CERT.read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _func(name):
    start = SRC.index(name + ' () {')
    return SRC[start:SRC.index('\n}\n', start) + 3]


class TestFixCertChainScopeEmptyAndTimeoutGuards(unittest.TestCase):
    @unittest.skipUnless(_find_bash(), '需要 bash')
    def test_masq_https_port_only_reads_inside_masquerade_section(self):
        """masq_https_port 必须只在顶层 masquerade: 段内读取 listenHTTPS，不得跨段误抓。"""
        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text(
                'listen: :443\n'
                'other_section:\n'
                '  listenHTTPS: :1111\n'
                'masquerade:\n'
                '  type: proxy\n'
                '  listenHTTPS: :8443\n',
                encoding='utf-8',
            )
            r = subprocess.run(
                [bash, '-c', _func('masq_https_port') + f'masq_https_port "{cfg.as_posix()}"\n'],
                capture_output=True, text=True, encoding='utf-8', timeout=15,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), '8443')

    @unittest.skipUnless(_find_bash(), '需要 bash')
    def test_empty_or_corrupt_cert_reports_no_pem_instead_of_leaf_only(self):
        """证书文件不含 BEGIN CERTIFICATE（COUNT=0）时须明确报不含有效 PEM，不得误报「仅 1 张证书」。"""
        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cert = td_path / 'empty.crt'
            cert.write_text('not a pem file\n', encoding='utf-8')
            cfg = td_path / 'config.yaml'
            cfg.write_text(f'tls:\n  cert: "{cert.as_posix()}"\n', encoding='utf-8')
            r = subprocess.run(
                [bash, str(FIX_CERT), '--dry-run', '--config', str(cfg)],
                capture_output=True, text=True, encoding='utf-8', timeout=15,
            )
            self.assertEqual(r.returncode, 1)
            combined = r.stdout + r.stderr
            self.assertNotIn('仅 1 张证书', combined)
            self.assertIn('PEM', combined)

    def test_backup_enforces_600_and_verify_handles_missing_timeout(self):
        """备份配置必须强制 chmod 600，验证链必须兼容无 timeout 命令的环境。"""
        self.assertIn('chmod 600 "$BK"', SRC)
        self.assertIn('command -v timeout', SRC)


if __name__ == '__main__':
    unittest.main()
