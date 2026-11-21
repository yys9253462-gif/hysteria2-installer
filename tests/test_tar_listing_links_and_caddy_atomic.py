"""回归测试：install.sh 的 hy2_tar_listing_safe 拦截链接/反斜杠/空包，以及 setup_cert_via_existing_caddy 先验候选再原子替换且拦截非法域名。"""

import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


def _pick_bash():
    if os.name == 'nt' and Path(r'C:\Program Files\Git\bin\bash.exe').exists():
        return r'C:\Program Files\Git\bin\bash.exe'
    return shutil.which('bash')


def _extract_fn(source: str, name: str) -> str:
    start = source.index(f'{name}() {{\n')
    lines = source[start:].splitlines(keepends=True)
    in_heredoc = None
    out = []
    for idx, line in enumerate(lines):
        out.append(line)
        if in_heredoc is not None:
            if line.strip() == in_heredoc:
                in_heredoc = None
            continue
        m_hd = re.search(r"<<-?\s*'?([A-Za-z0-9_]+)'?", line)
        if m_hd:
            in_heredoc = m_hd.group(1)
            continue
        if idx > 0 and line == '}\n':
            break
    return ''.join(out)


class TarListingLinksAndCaddyAtomicTests(unittest.TestCase):
    def test_hy2_tar_listing_safe_blocks_symlink_backslash_and_empty_archive(self):
        """hy2_tar_listing_safe 必须拒绝含符号链接、反斜杠或空清单的 tar.gz，并放行合法常规包。"""
        bash = _pick_bash()
        if not bash:
            self.skipTest('无可用 bash')
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'hy2_tar_listing_safe')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 1) 含符号链接
            sym_tar = root / 'sym.tar.gz'
            with tarfile.open(sym_tar, 'w:gz') as tf:
                ti = tarfile.TarInfo('gost')
                ti.type = tarfile.SYMTYPE
                ti.linkname = '/etc/passwd'
                tf.addfile(ti)
            # 2) 含反斜杠路径
            bs_tar = root / 'bs.tar.gz'
            with tarfile.open(bs_tar, 'w:gz') as tf:
                data = b'abc'
                ti = tarfile.TarInfo('a\\b')
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            # 3) 空归档
            empty_tar = root / 'empty.tar.gz'
            with tarfile.open(empty_tar, 'w:gz'):
                pass
            # 4) 合法普通文件
            ok_tar = root / 'ok.tar.gz'
            with tarfile.open(ok_tar, 'w:gz') as tf:
                data = b'ok-binary'
                ti = tarfile.TarInfo('gost')
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))

            def run_check(tar_path: Path) -> int:
                runner = root / 'chk.sh'
                runner.write_bytes((f'{fn}\nhy2_tar_listing_safe "{tar_path.as_posix()}"\n').encode('utf-8'))
                res = subprocess.run([bash, runner.as_posix()], capture_output=True, text=True, timeout=15)
                return res.returncode

            self.assertNotEqual(run_check(sym_tar), 0, '含符号链接的 tar.gz 不应通过校验')
            self.assertNotEqual(run_check(bs_tar), 0, '含反斜杠路径的 tar.gz 不应通过校验')
            self.assertNotEqual(run_check(empty_tar), 0, '空 tar.gz 不应通过校验')
            self.assertEqual(run_check(ok_tar), 0, '合法普通文件 tar.gz 应通过校验')

    def test_setup_cert_via_existing_caddy_validates_candidate_before_touching_live_file_and_blocks_bad_domain(self):
        """非法域名应被拒绝；caddy validate 失败时不得直接改写生产 Caddyfile，也不得残留临时文件。"""
        bash = _pick_bash()
        if not bash:
            self.skipTest('无可用 bash')
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn_caddy = _extract_fn(src, 'setup_cert_via_existing_caddy')
        fn_decoy = _extract_fn(src, 'caddy_decoy_directives')
        self.assertNotIn('cat >> "$cf"', fn_caddy, '不得直接向生产 Caddyfile 就地追加')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cf = root / 'Caddyfile'
            original = 'prod.example.com {\n    respond "live"\n}\n'
            cf.write_text(original, encoding='utf-8', newline='\n')
            fn_patched = fn_caddy.replace('/etc/caddy/Caddyfile', cf.as_posix())

            # 1) 含花括号注入的非法域名必须拒绝
            runner_bad = root / 'bad_domain.sh'
            runner_bad.write_bytes(('\n'.join([
                'set -uo pipefail',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                'caddy() { return 0; }',
                'find_cert_in_webserver() { return 1; }',
                fn_decoy,
                fn_patched,
                'setup_cert_via_existing_caddy "evil.com { respond 1 }"',
            ]) + '\n').encode('utf-8'))
            r1 = subprocess.run([bash, runner_bad.as_posix()], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(r1.returncode, 0, '非法域名应被拒绝')
            self.assertEqual(cf.read_text(encoding='utf-8'), original)

            # 2) validate 失败时验证传入的是临时候选文件而非生产 Caddyfile，且无残留
            seen_arg = root / 'seen.txt'
            runner_val = root / 'val_fail.sh'
            runner_val.write_bytes(('\n'.join([
                'set -uo pipefail',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                f'caddy() {{ printf "%s\\n" "$*" > "{seen_arg.as_posix()}"; return 1; }}',
                'find_cert_in_webserver() { return 1; }',
                fn_decoy,
                fn_patched,
                'setup_cert_via_existing_caddy "new-node.example.com"',
            ]) + '\n').encode('utf-8'))
            r2 = subprocess.run([bash, runner_val.as_posix()], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(r2.returncode, 0)
            self.assertEqual(cf.read_text(encoding='utf-8'), original)
            self.assertIn('.hy2-tmp.', seen_arg.read_text(encoding='utf-8'))
            leftovers = [p.name for p in root.iterdir() if '.hy2-tmp.' in p.name]
            self.assertEqual(leftovers, [], f'残留候选临时文件: {leftovers}')


if __name__ == '__main__':
    unittest.main()
