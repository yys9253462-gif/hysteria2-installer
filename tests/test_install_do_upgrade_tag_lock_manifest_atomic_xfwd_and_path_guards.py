"""回归测试：install.sh 中 do_upgrade.sh 符号链接与追加锁、TAG 防路径穿越、hashes.txt 严双列与多层 ./ 剥离、curl 体积上限、xForwarded 原子写及 PathChanged 防换行注入。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


def _extract_do_upgrade() -> str:
    m = re.search(r"cat > \"\$HY2_DIR/do_upgrade\.sh\" <<'EOUG'\n(.*?)\nEOUG\n", INSTALL_SH, re.S)
    assert m, 'install.sh 中未找到 do_upgrade.sh heredoc'
    return m.group(1)


class TestInstallDoUpgradeGuardsBatch60(unittest.TestCase):
    def test_write_do_upgrade_sh_clears_symlink_first(self):
        """generate_server_config 写 do_upgrade.sh 前必须先移除符号链接防劫持。"""
        idx = INSTALL_SH.index('cat > "$HY2_DIR/do_upgrade.sh"')
        before = INSTALL_SH[max(0, idx - 200):idx]
        self.assertIn('[[ ! -L "$HY2_DIR/do_upgrade.sh" ]] || rm -f "$HY2_DIR/do_upgrade.sh"', before)

    def test_do_upgrade_core_lock_rejects_symlink_and_uses_append(self):
        """do_upgrade.sh core 打开核心锁前必须拒符号链接并改用追加重定向 exec 9>>。"""
        body = _extract_do_upgrade()
        self.assertIn('[[ ! -L "${HY2_DIR}/.core-operation.lock" ]]', body)
        self.assertIn('exec 9>>"${HY2_DIR}/.core-operation.lock"', body)
        self.assertNotIn('exec 9>"${HY2_DIR}/.core-operation.lock"', body)

    def test_do_upgrade_core_validates_tag_and_bounds_curls_and_atomic_xforwarded(self):
        """do_upgrade.sh core 必须拦截路径穿越 TAG、给 curl 设 --max-filesize、原子写 xForwarded 且无 sed -i。"""
        body = _extract_do_upgrade()
        self.assertIn('^(app/)?v[0-9A-Za-z._-]+$', body, '必须用正则严格校验 TAG 格式')
        self.assertIn('--max-filesize 2097152', body)
        self.assertIn('--max-filesize 104857600', body)
        self.assertIn('--max-filesize 10485760', body)
        self.assertNotIn('xForwarded: true/\' "$HY2_DIR/config.yaml"', body,
                         '不得直接对生产 config.yaml 就地 sed -i 写入 xForwarded')
        self.assertIn('xForwarded: true/\' "$_xfwd_tmp"', body,
                      'xForwarded 必须先在同目录临时副本上改写再原子 mv 替换')
        self.assertIn('.config.yaml.xfwd.XXXXXX', body)

    def test_do_upgrade_hashes_awk_rejects_comments_extra_cols_and_strips_multi_dot_slash(self):
        """hashes.txt 解析 awk 必须忽略注释、要求 NF==2 且循环剥离多层 ./。"""
        body = _extract_do_upgrade()
        m = re.search(r'WANT="\$\(awk -v a="\$ASSET" \'(.*?)\'', body, re.S)
        self.assertIsNotNone(m, '未找到 hashes.txt awk 解析段')
        awk_prog = m.group(1)
        self.assertIn('NF==2', awk_prog)
        self.assertIn('while (sub(/^\\.\\//,"",n))', awk_prog)

        if BASH:
            with tempfile.TemporaryDirectory() as td:
                manifest = Path(td) / 'hashes.txt'
                good_sha = 'a' * 64
                bad_sha = 'b' * 64
                manifest.write_text(
                    f'# {bad_sha} hysteria-linux-amd64\n'
                    f'{bad_sha} hysteria-linux-amd64 extra_col\n'
                    f'{good_sha} ././hysteria-linux-amd64\n',
                    encoding='utf-8',
                )
                r = subprocess.run(
                    [BASH, '-c', f'ASSET=hysteria-linux-amd64; awk -v a="$ASSET" \'{awk_prog}\' "$1" | tr A-F a-f | sort -u',
                     '_', str(manifest)],
                    capture_output=True, text=True, timeout=15
                )
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), good_sha)

    def test_do_upgrade_portal_sets_cleanup_trap_and_sanitizes_path_changed(self):
        """do_upgrade.sh portal 必须注册 _bundle_dir/_bundle_map EXIT 清理陷阱并拦 _cwd 换行注入。"""
        body = _extract_do_upgrade()
        self.assertIn('trap \'_rc=$?; rm -f "${_bundle_map:-}"; [[ $_rc -ne 0 ]] && rm -rf "${_bundle_dir:-}"\' EXIT', body)
        self.assertIn('[[ "$_cwd" == *$', body, '写入 PathChanged 前必须拦截换行/回车控制字符')


if __name__ == '__main__':
    unittest.main()
