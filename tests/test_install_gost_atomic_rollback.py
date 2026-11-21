"""回归测试：install.sh 的 install_gost 回滚免疫 ETXTBSY（同目录原子替换）且不残留临时备份与 gost.new。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')


def _extract_fn(source: str, name: str) -> str:
    start = source.index(f'{name}() {{\n')
    # 一直切到下一个顶格分隔注释，避开内部嵌的 Python 脚本里的 `}` 与多处 heredoc。
    end = source.index('\n# ==============================================================================\n# AmneziaWG', start)
    return source[start:end].rstrip() + '\n'


@unittest.skipUnless(BASH, '需要 bash 环境')
class InstallGostAtomicRollbackTests(unittest.TestCase):
    def test_restore_gost_install_replaces_binary_atomically_avoiding_etxtbsy(self):
        """回滚时不得直接 cp -p 覆写运行中的 $GOST_BIN，必须经同目录临时文件 mv -f 原子替换。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'install_gost')
        restore_part = fn[fn.index('_restore_gost_asset() {'):fn.index('# 先从该版本的官方')]
        self.assertNotIn('cp -p "$old_gost" "$GOST_BIN"', restore_part,
                         '_restore_gost_install 仍直接 cp -p 覆写运行中的 $GOST_BIN（Linux 会报 ETXTBSY）')
        self.assertIn('mv -f', restore_part, '_restore_gost_install 应经同目录临时文件 mv -f 原子回滚')

    def test_mv_failure_cleans_gost_new_and_backup_failure_cleans_temp_files(self):
        """替换失败时必须删除 gost.new；备份中途失败时必须清理已创建的临时备份文件。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'install_gost')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hy2_dir = root / 'etc/hysteria'
            usr_bin = root / 'usr/local/bin'
            sysd = root / 'etc/systemd/system'
            tmp_home = root / 'tmp_work'
            for d in (hy2_dir, usr_bin, sysd, tmp_home):
                d.mkdir(parents=True, exist_ok=True)
            (usr_bin / 'gost').write_text('old-bin', encoding='utf-8')
            (sysd / 'gost.service').write_text('ExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml -R 30s\n', encoding='utf-8')
            (hy2_dir / '.hy2-gost-owned').write_text('', encoding='utf-8')
            (hy2_dir / 'gost.yml').write_text('secret-cfg', encoding='utf-8')

            fn_patched = (
                fn.replace('GOST_BIN="/usr/local/bin/gost"', f'GOST_BIN="{(usr_bin / "gost").as_posix()}"')
                  .replace('GOST_UNIT="/etc/systemd/system/gost.service"', f'GOST_UNIT="{(sysd / "gost.service").as_posix()}"')
                  .replace('/usr/local/lib/hy2-gost-selfcheck', (root / 'selfcheck').as_posix())
            )
            # 场景 1：mv -f "${GOST_BIN}.new" "$GOST_BIN" 失败，gost.new 不得残留
            script1 = '\n'.join([
                'set -uo pipefail',
                f'TMPDIR="{tmp_home.as_posix()}"',
                f'HY2_DIR="{hy2_dir.as_posix()}"',
                'HY2_ARCH=amd64',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                'systemctl() { return 0; }',
                'curl() { echo "{}"; }',
                'jq() { echo ""; }',
                'hy2_expected_sha256() { echo deadbeef; }',
                'hy2_verify_sha256() { return 0; }',
                'hy2_tar_listing_safe() { return 0; }',
                'hy2_tar_find_member() { echo gost; }',
                'tar() { printf new-bin > "$TMP_DIR/gost"; }',
                'mv() { if [[ "$*" == *"gost.new"* ]]; then return 1; fi; command mv "$@"; }',
                fn_patched,
                'install_gost; echo "RC=$?"',
            ])
            s1_path = root / 'run1.sh'
            s1_path.write_text(script1 + '\n', encoding='utf-8', newline='\n')
            res1 = subprocess.run([BASH, str(s1_path)], capture_output=True, text=True,
                                  encoding='utf-8', errors='replace', timeout=20)
            self.assertIn('RC=1', res1.stdout, res1.stdout + res1.stderr)
            self.assertFalse((usr_bin / 'gost.new').exists(), '替换失败后仍残留 gost.new')
            self.assertEqual((usr_bin / 'gost').read_text(encoding='utf-8'), 'old-bin')

            # 场景 2：备份 gost.yml 失败时，前面已建的 gost/unit 临时备份必须清理干净
            script2 = '\n'.join([
                'set -uo pipefail',
                f'TMPDIR="{tmp_home.as_posix()}"',
                f'HY2_DIR="{hy2_dir.as_posix()}"',
                'HY2_ARCH=amd64',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                'systemctl() { return 0; }',
                'curl() { echo "{}"; }',
                'jq() { echo ""; }',
                'cp() { if [[ "$*" == *"gost.yml"* ]]; then return 1; fi; command cp "$@"; }',
                fn_patched,
                'install_gost; echo "RC=$?"',
            ])
            s2_path = root / 'run2.sh'
            s2_path.write_text(script2 + '\n', encoding='utf-8', newline='\n')
            res2 = subprocess.run([BASH, str(s2_path)], capture_output=True, text=True,
                                  encoding='utf-8', errors='replace', timeout=20)
            self.assertIn('RC=1', res2.stdout, res2.stdout + res2.stderr)
            leftovers = list(tmp_home.iterdir())
            self.assertEqual(leftovers, [], f'备份中途失败泄漏了临时备份文件: {leftovers}')


if __name__ == '__main__':
    unittest.main()
