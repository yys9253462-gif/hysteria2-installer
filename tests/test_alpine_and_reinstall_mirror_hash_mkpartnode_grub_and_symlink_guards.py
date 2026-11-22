"""回归测试：alpine2debian.sh 与 reinstall-debian13.sh 的镜像禁用 #/? 防 APT 截断、is_whole_disk 防横杠选项注入、mk_partnode 校验纯数字主次号、grub.cfg 非空校验、防符号链接及 installnet_looks_valid 拒符号链接与超长位数。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
A2D = (ROOT / 'alpine2debian.sh').read_text(encoding='utf-8')
RD13 = (ROOT / 'reinstall-debian13.sh').read_text(encoding='utf-8')
SH = shutil.which('sh')


def _extract_precheck(src: str, stop_marker: str) -> str:
    return src[:src.index(stop_marker)] + '\necho "PRECHECK_OK"\n'


class TestAlpineAndReinstallBatch60Guards(unittest.TestCase):
    def test_mirror_rejects_hash_and_query_in_both_scripts(self):
        """两份重装脚本均必须拦截含 # 或 ? 的 MIRROR URL，防止破坏 sources.list 或注入。"""
        self.assertIn('*[!A-Za-z0-9._~:/%+-]*', A2D)
        self.assertIn('*[!A-Za-z0-9._~:/%+-]*', RD13)
        if SH:
            for name, src, stop in (
                ('alpine2debian.sh', A2D, '# ── 第 1 步：环境检查'),
                ('reinstall-debian13.sh', RD13, '# 初始化日志'),
            ):
                script = _extract_precheck(src, stop)
                env = {k: v for k, v in os.environ.items()
                       if k not in ('MIRROR', 'SECURITY_MIRROR', 'DEBIAN_SUITE', 'HOSTNAME',
                                    'TIMEZONE', 'SWAP_MB', 'PORT', 'PASSWORD', 'DISK', 'RELEASE', 'NET_MODE', 'LOG')}
                for bad_url in ('https://deb.debian.org/debian#comment', 'https://deb.debian.org/debian?x=1'):
                    r = subprocess.run(
                        [SH, '-c', script, '_', '--mirror', bad_url],
                        capture_output=True, text=True, encoding='utf-8', errors='replace',
                        env=env, timeout=15,
                    )
                    self.assertNotEqual(r.returncode, 0, f'{name} 应拒绝非法镜像地址 {bad_url}')

    def test_is_whole_disk_passes_double_dash_to_readlink_and_basename(self):
        """两份脚本的 is_whole_disk 必须向 readlink/basename 传 -- 防止前导横杠被当选项。"""
        for label, src in (('alpine2debian.sh', A2D), ('reinstall-debian13.sh', RD13)):
            m = re.search(r'(?m)^is_whole_disk\(\)\s*\{.*?\n\}', src, re.S)
            self.assertIsNotNone(m, f'{label} 缺少 is_whole_disk')
            body = m.group(0)
            self.assertIn('readlink -f -- "$1"', body, f'{label} readlink 必须加 --')
            self.assertIn('basename -- "$_wd_resolved"', body, f'{label} basename 必须加 --')

    def test_alpine2debian_mk_partnode_grub_cfg_and_symlink_guards(self):
        """alpine2debian.sh 必须校验 mk_partnode 纯数字主次设备号、写 resolv/interfaces/swapfile 前防符号链接、且验证 grub.cfg 非空。"""
        m = re.search(r'mk_partnode\(\)\s*\{.*?\n    \}', A2D, re.S)
        self.assertIsNotNone(m, '未找到 mk_partnode')
        mk_body = m.group(0)
        self.assertIn('case "$_maj:$_min" in', mk_body, 'mk_partnode 必须校验主次设备号为纯数字')

        self.assertIn('[ ! -L "$MOUNT_DIR/etc/resolv.conf" ] || rm -f "$MOUNT_DIR/etc/resolv.conf"', A2D)
        self.assertIn('[ ! -L "$MOUNT_DIR/etc/network/interfaces" ] || rm -f "$MOUNT_DIR/etc/network/interfaces"', A2D)
        self.assertIn('[ ! -L "$MOUNT_DIR/swapfile" ] || rm -f "$MOUNT_DIR/swapfile"', A2D)
        self.assertIn('[ -s "$MOUNT_DIR/boot/grub/grub.cfg" ] || die', A2D)

    def test_reinstall_installnet_looks_valid_rejects_symlink_and_overlong_digits(self):
        """reinstall-debian13.sh 的 installnet_looks_valid 必须拒绝符号链接并限制字节数字长度 <= 8。"""
        m = re.search(r'(?m)^installnet_looks_valid\(\)\s*\{.*?\n\}', RD13, re.S)
        self.assertIsNotNone(m, '未找到 installnet_looks_valid')
        body = m.group(0)
        self.assertIn('[ ! -L "$IN_FILE" ]', body)
        self.assertIn('[ "${#_got}" -le 8 ]', body)


if __name__ == '__main__':
    unittest.main()
