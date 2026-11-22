import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALPINE_SH = ROOT / 'alpine2debian.sh'
REINSTALL_SH = ROOT / 'reinstall-debian13.sh'


def _sh_exe():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('sh') or shutil.which('bash')


def _extract_fn(src, name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'未找到函数 {name}()')
    return m.group(0)


def _to_unix_path(sh_exe, p):
    if 'Git' in sh_exe and ':' in str(p):
        s = str(p).replace('\\', '/')
        return '/' + s[0].lower() + s[2:]
    return Path(p).as_posix()


class ReinstallAndAlpine2DebianDnsPwdDiskAndSizeGuardTests(unittest.TestCase):
    def setUp(self):
        self.alpine = ALPINE_SH.read_text(encoding='utf-8').replace('\r\n', '\n')
        self.reinstall = REINSTALL_SH.read_text(encoding='utf-8').replace('\r\n', '\n')

    def test_is_whole_disk_rejects_empty_dot_dotdot_and_slash(self):
        sh = _sh_exe()
        if not sh:
            self.skipTest('缺少 sh/bash 环境')
        with tempfile.TemporaryDirectory() as td:
            sys_block = Path(td) / 'sys_block'
            (sys_block / 'vda').mkdir(parents=True)
            sb_unix = _to_unix_path(sh, sys_block)
            for label, src in (('alpine2debian.sh', self.alpine), ('reinstall-debian13.sh', self.reinstall)):
                fn = _extract_fn(src, 'is_whole_disk')
                for bad in ('', '/', '.', '..'):
                    with self.subTest(script=label, bad=bad):
                        cmd = f'SYS_BLOCK="{sb_unix}"\n{fn}\nis_whole_disk "$1" && echo OK || echo BAD'
                        proc = subprocess.run([sh, '-c', cmd, '_', bad], capture_output=True, text=True, timeout=15)
                        self.assertEqual(proc.stdout.strip(), 'BAD', f'{label} 误放行了 {bad!r}')

    def test_disk_mounts_does_not_treat_dots_in_device_as_regex_wildcard(self):
        sh = _sh_exe()
        if not sh:
            self.skipTest('缺少 sh/bash 环境')
        with tempfile.TemporaryDirectory() as td:
            mounts = Path(td) / 'mounts'
            mounts.write_text(
                '/dev/diskXa1 /mnt/other ext4 rw 0 0\n'
                '/dev/disk.a1 /mnt/target ext4 rw 0 0\n',
                encoding='utf-8',
            )
            m_unix = _to_unix_path(sh, mounts)
            for label, src in (('alpine2debian.sh', self.alpine), ('reinstall-debian13.sh', self.reinstall)):
                fn = _extract_fn(src, 'disk_mounts')
                with self.subTest(script=label):
                    cmd = f'{fn}\ndisk_mounts "/dev/disk.a" "{m_unix}"'
                    proc = subprocess.run([sh, '-c', cmd], capture_output=True, text=True, timeout=15)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    lines = [l for l in proc.stdout.splitlines() if l.strip()]
                    self.assertEqual(lines, ['/mnt/target'], f'{label} 误命中正则通配设备: {lines}')

    def test_alpine_dns_host_strips_port_and_ipv6_brackets(self):
        sh = _sh_exe()
        if not sh:
            self.skipTest('缺少 sh/bash 环境')
        m = re.search(r'^DNS_HOST=.*$', self.alpine, re.M)
        self.assertIsNotNone(m)
        line = m.group(0)
        cases = [
            ('http://mirrors.example.com:8080/debian', 'mirrors.example.com'),
            ('https://[2001:db8::1]:8443/debian', '2001:db8::1'),
            ('http://mirrors.aliyun.com/debian', 'mirrors.aliyun.com'),
        ]
        for mirror, expected in cases:
            with self.subTest(mirror=mirror):
                cmd = f'MIRROR="$1"\n{line}\nprintf "%s" "$DNS_HOST"'
                proc = subprocess.run([sh, '-c', cmd, '_', mirror], capture_output=True, text=True, timeout=15)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout.strip(), expected)

    def test_alpine_rejects_control_chars_in_root_pwd_before_wiping_disk(self):
        # 必须在清盘之前拦截 ROOT_PWD 中的换行或回车等控制字符，避免 chpasswd 中断
        pwd_pos = self.alpine.index('[ -n "$ROOT_PWD" ] || die "root 密码不能为空"')
        wipe_pos = self.alpine.index('info "第 5/9 步：分区并格式化 $DISK"')
        segment = self.alpine[pwd_pos:wipe_pos]
        self.assertIn('[:cntrl:]', segment)

    def test_reinstall_installnet_looks_valid_enforces_upper_size_bound(self):
        fn = _extract_fn(self.reinstall, 'installnet_looks_valid')
        self.assertIn('2097152', fn)
        sh = _sh_exe()
        if not sh:
            self.skipTest('缺少 sh/bash 环境')
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / 'InstallNET.sh'
            big.write_bytes(b'#!/bin/bash\n' + b'a' * (2 * 1024 * 1024 + 64))
            bp = _to_unix_path(sh, big)
            cmd = f'IN_FILE="{bp}"\n{fn}\ninstallnet_looks_valid && echo OK || echo BAD'
            proc = subprocess.run([sh, '-c', cmd], capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.stdout.strip(), 'BAD')


if __name__ == '__main__':
    unittest.main()
