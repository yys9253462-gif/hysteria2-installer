import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / 'install.sh'


def _bash_exe():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('bash')


def _extract_fn(src, name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


def _to_bash_path(bash_exe, p):
    if 'Git' in bash_exe and ':' in str(p):
        s = str(p).replace('\\', '/')
        return '/' + s[0].lower() + s[2:]
    return Path(p).as_posix()


class InstallCertCountManifestDecoyAndSubportGuardTests(unittest.TestCase):
    def setUp(self):
        self.src = INSTALL_SH.read_text(encoding='utf-8').replace('\r\n', '\n')

    def test_pem_cert_count_ignores_csr_and_comments(self):
        fn = _extract_fn(self.src, 'pem_cert_count')
        self.assertIn('-----BEGIN CERTIFICATE-----', fn)
        bash = _bash_exe()
        if not bash:
            self.skipTest('缺少 bash 环境')
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / 'mixed.pem'
            f.write_text(
                '# comment mentioning BEGIN CERTIFICATE\n'
                '-----BEGIN CERTIFICATE REQUEST-----\n'
                'MIIB\n'
                '-----END CERTIFICATE REQUEST-----\n'
                '-----BEGIN CERTIFICATE-----\r\n'
                'MIIC\r\n'
                '-----END CERTIFICATE-----\r\n',
                encoding='utf-8',
            )
            bp = _to_bash_path(bash, f)
            proc = subprocess.run(
                [bash, '-c', f'{fn}\npem_cert_count "{bp}"'],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), '1', f'应只统计 1 张正式证书，实际={proc.stdout!r}')

    def test_hy2_manifest_sha256_strips_multiple_dot_slashes_and_indented_comments(self):
        fn = _extract_fn(self.src, 'hy2_manifest_sha256')
        bash = _bash_exe()
        if not bash:
            self.skipTest('缺少 bash 环境')
        sha = 'a' * 64
        with tempfile.TemporaryDirectory() as td:
            mfile = Path(td) / 'checksums.txt'
            mfile.write_text(
                f'   # build/hysteria-linux-amd64\n'
                f'{sha}  ././build/hysteria-linux-amd64\n',
                encoding='utf-8',
            )
            bp = _to_bash_path(bash, mfile)
            proc = subprocess.run(
                [bash, '-c', f'{fn}\nhy2_manifest_sha256 "{bp}" "build/hysteria-linux-amd64"'],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), sha)

    def test_hy2_fetch_manifest_has_max_filesize(self):
        fn = _extract_fn(self.src, 'hy2_fetch_manifest')
        self.assertIn('--max-filesize', fn)

    def test_caddy_decoy_directives_sanitizes_backticks_and_html(self):
        fn = _extract_fn(self.src, 'caddy_decoy_directives')
        bash = _bash_exe()
        if not bash:
            self.skipTest('缺少 bash 环境')
        proc = subprocess.run(
            [bash, '-c', fn + '\ncaddy_decoy_directives \'evil`<script>alert(1)</script>.example.com\''],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        # 反引号只能成对出现在 respond `...` 两侧，正文不能被注入多余反引号或 <script>
        self.assertEqual(out.count('`'), 2, f'占位页中出现额外反引号破坏 Caddyfile 语法:\n{out}')
        self.assertNotIn('<script>', out)

    def test_select_subscription_port_rejects_leading_zero_string_ports(self):
        fn = _extract_fn(self.src, 'select_subscription_port')
        self.assertGreaterEqual(fn.count("startswith('0')"), 3)


if __name__ == '__main__':
    unittest.main()
