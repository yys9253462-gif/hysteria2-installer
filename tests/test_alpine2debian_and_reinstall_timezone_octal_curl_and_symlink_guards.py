"""回归测试：alpine2debian.sh 与 reinstall-debian13.sh 时区/主机名边界、十进制扇区防八进制溢出、curl限流优先与符号链接防护。"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ALPINE_SH = (REPO / 'alpine2debian.sh').read_text(encoding='utf-8')
REINSTALL_SH = (REPO / 'reinstall-debian13.sh').read_text(encoding='utf-8')


def _find_sh():
    for cand in (r'C:\Program Files\Git\bin\sh.exe', shutil.which('sh'), r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 sh')


class Alpine2DebianAndReinstallTimezoneOctalCurlAndSymlinkGuardsTests(unittest.TestCase):
    def test_alpine2debian_guards_hostname_timezone_octal_sectors_and_symlinks(self):
        """alpine2debian.sh 须限制 HOSTNAME 长度与连续点号、禁 TIMEZONE 前导连字符、校验 zoneinfo 存在、去前导零防八进制算术错及保护 resolv/fstab 符号链接。"""
        self.assertIn('[ "${#HOSTNAME}" -le 63 ]', ALPINE_SH)
        self.assertIn("''|-*|/*|*..*|*[!A-Za-z0-9_/+.-]*", ALPINE_SH)
        self.assertIn('[ -f "/usr/share/zoneinfo/${TIMEZONE}" ]', ALPINE_SH)
        self.assertIn('readlink -f -- "$DISK"', ALPINE_SH)
        self.assertIn('[ ! -L /etc/resolv.conf ]', ALPINE_SH)
        self.assertIn('[ ! -L "$MOUNT_DIR/etc/fstab" ]', ALPINE_SH)
        # 扇区数须剥离前导零防 POSIX shell 八进制求值异常（如 08）
        self.assertIn('_raw_sectors="${_raw_sectors#"${_raw_sectors%%[!0]*}"}"', ALPINE_SH)

    def test_reinstall_debian13_prefers_bounded_curl_and_guards_octal_sectors_and_resolv_symlink(self):
        """reinstall-debian13.sh 须优先使用带 --max-filesize 的 curl、剥离扇区前导零、加 -- 防护并保护 /etc/resolv.conf 符号链接。"""
        self.assertIn('readlink -f -- "$DISK"', REINSTALL_SH)
        self.assertIn('_raw_sectors="${_raw_sectors#"${_raw_sectors%%[!0]*}"}"', REINSTALL_SH)
        self.assertIn('[ ! -L /etc/resolv.conf ]', REINSTALL_SH)
        m = re.search(r'download_installnet\(\)\s*\{.*?\n\}', REINSTALL_SH, re.S)
        self.assertIsNotNone(m)
        fn = m.group(0)
        self.assertIn('[ ! -L "$IN_FILE" ]', fn)
        # curl (--max-filesize 2097152) 必须排在 wget 之前优先执行，避免不限大小流撑爆内存救援盘
        self.assertLess(fn.index('command -v curl'), fn.index('command -v wget'))

        # 运行时验证：curl 失败后仍可正常回退 wget 且无需预定义 WORKDIR
        sh = _find_sh()
        import tempfile
        m_valid = re.search(r'installnet_looks_valid\(\)\s*\{.*?\n\}', REINSTALL_SH, re.S)
        self.assertIsNotNone(m_valid)
        with tempfile.TemporaryDirectory() as td:
            in_p = (Path(td) / 'InstallNET.sh').as_posix()
            if len(in_p) >= 2 and in_p[1] == ':':
                in_p = '/' + in_p[0].lower() + in_p[2:]
            script = (
                'set -u\n'
                f'IN_FILE="{in_p}"\n'
                'INSTALLNET_URL="https://example.com/a.sh"\n'
                'INSTALLNET_MIRROR="https://example.com/b.sh"\n'
                'curl() { echo "CURL_TRIED"; return 7; }\n'
                'wget() { echo "WGET_FALLBACK"; { echo "#!/bin/bash"; i=0; while [ $i -lt 2000 ]; do echo "# pad line 12345678901234567890"; i=$((i+1)); done; } > "$2"; return 0; }\n'
                + m_valid.group(0) + '\n'
                + fn + '\n'
                + 'download_installnet\n'
                + 'echo "DL_OK"\n'
            )
            res = subprocess.run([sh, '-c', script], capture_output=True, text=True, errors='replace', timeout=20)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('CURL_TRIED', res.stdout)
            self.assertIn('WGET_FALLBACK', res.stdout)
            self.assertIn('DL_OK', res.stdout)

    def test_alpine2debian_rejects_leading_dash_timezone_and_overlong_hostname_at_runtime(self):
        """运行时验证：alpine2debian.sh 前置校验须拒绝前导连字符 TIMEZONE 与超 63 字节 HOSTNAME。"""
        sh = _find_sh()
        # 仅抽取前置参数校验片段在 sh 下执行验证
        start = ALPINE_SH.index('# 前置参数校验：')
        end = ALPINE_SH.index('# 提示里的版本跟着 --suite 走', start)
        snippet = ALPINE_SH[start:end]
        for label, env_assign in (
            ('bad_tz', 'SWAP_MB=0; DEBIAN_SUITE=bookworm; HOSTNAME=debian; TIMEZONE=-Asia/Shanghai; MIRROR=http://deb.debian.org/debian; SECURITY_MIRROR=http://security.debian.org/debian-security'),
            ('long_host', 'SWAP_MB=0; DEBIAN_SUITE=bookworm; HOSTNAME=' + ('a' * 64) + '; TIMEZONE=Asia/Shanghai; MIRROR=http://deb.debian.org/debian; SECURITY_MIRROR=http://security.debian.org/debian-security'),
        ):
            script = (
                'set -eu\n'
                'die() { printf "DIE:%s\\n" "$*" >&2; exit 1; }\n'
                + env_assign + '\n'
                + snippet + '\n'
                + 'echo PASSED\n'
            )
            res = subprocess.run([sh, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertNotEqual(res.returncode, 0, f'{label} 应被前置校验拒绝: {res.stdout}{res.stderr}')
            self.assertIn('DIE:', res.stderr)


if __name__ == '__main__':
    unittest.main()
