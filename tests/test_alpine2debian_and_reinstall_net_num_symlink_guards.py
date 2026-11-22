"""回归测试：alpine2debian.sh 与 reinstall-debian13.sh 的整数防溢出、网络配置格式校验、DNS 主机防选项注入与符号链接防护。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALPINE_SH = ROOT / 'alpine2debian.sh'
REINSTALL_SH = ROOT / 'reinstall-debian13.sh'


def _sh_exe():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('sh') or shutil.which('bash')


def _to_unix_path(sh_exe: str, p: Path) -> str:
    if 'Git' in sh_exe and ':' in str(p):
        s = str(p).replace('\\', '/')
        return '/' + s[0].lower() + s[2:]
    return Path(p).as_posix()


def _extract_fn(src: str, name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'未找到函数 {name}()')
    return m.group(0)


def _run_alpine_setup(src: str, cli=(), env=None) -> subprocess.CompletedProcess:
    sh = _sh_exe()
    full = {
        k: v
        for k, v in os.environ.items()
        if k not in ('MIRROR', 'SECURITY_MIRROR', 'DEBIAN_SUITE', 'HOSTNAME', 'TIMEZONE', 'SWAP_MB')
    }
    if env:
        full.update(env)
    region = src[src.index('# ── 默认值'):src.index('# ── 第 1 步')]
    args = ' '.join("'" + a.replace("'", "'\"'\"'") + "'" for a in cli)
    body = (f'set -- {args}\n' if cli else 'set --\n') + region + 'echo "OK"\n'
    return subprocess.run(
        [sh, '-c', body],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        env=full,
        timeout=20,
    )


def _run_reinstall_setup(src: str, cli=(), env=None) -> subprocess.CompletedProcess:
    sh = _sh_exe()
    full = {
        k: v
        for k, v in os.environ.items()
        if k not in ('PORT', 'PASSWORD', 'DISK', 'MIRROR', 'RELEASE', 'SWAP_MB', 'NET_MODE', 'LOG')
    }
    if env:
        full.update(env)
    region = src[src.index('# ── 常量'):src.index('# 初始化日志')]
    args = ' '.join("'" + a.replace("'", "'\"'\"'") + "'" for a in cli)
    body = (f'set -- {args}\n' if cli else 'set --\n') + region + 'echo "OK"\n'
    return subprocess.run(
        [sh, '-c', body],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        env=full,
        timeout=20,
    )


class AlpineAndReinstallNetNumSymlinkGuardsTests(unittest.TestCase):
    def setUp(self):
        self.sh = _sh_exe()
        if not self.sh:
            self.skipTest('缺少 sh/bash 环境')
        self.alpine = ALPINE_SH.read_text(encoding='utf-8').replace('\r\n', '\n')
        self.reinstall = REINSTALL_SH.read_text(encoding='utf-8').replace('\r\n', '\n')

    def test_alpine_rejects_leading_zero_and_oversized_swap_mb(self):
        """alpine2debian.sh 应拒绝前导零与超长位数 SWAP_MB，同时放行 0 与常规正整数。"""
        for bad in ('0512', '00', '1000000', '999999999999999999999'):
            with self.subTest(bad=bad):
                res = _run_alpine_setup(self.alpine, env={'SWAP_MB': bad})
                self.assertNotEqual(res.returncode, 0, f'SWAP_MB={bad!r} 应被拒绝，却通过: {res.stdout}')
        for good in ('0', '512', '65536'):
            with self.subTest(good=good):
                res = _run_alpine_setup(self.alpine, env={'SWAP_MB': good})
                self.assertEqual(res.returncode, 0, f'SWAP_MB={good!r} 应放行: {res.stderr}')

    def test_reinstall_rejects_oversized_port_release_and_bad_swap_mb(self):
        """reinstall-debian13.sh 应限制 PORT/RELEASE/SWAP_MB 位数并拒绝前导零 SWAP_MB。"""
        bad_cases = [
            ('超长 PORT', {'PORT': '9999999999999999999999'}),
            ('前导零 SWAP_MB', {'SWAP_MB': '0512'}),
            ('超长 SWAP_MB', {'SWAP_MB': '999999999999999999999'}),
            ('超长 RELEASE', {'RELEASE': '999999999999999999999'}),
            ('三位 RELEASE', {'RELEASE': '123'}),
        ]
        for label, env in bad_cases:
            with self.subTest(label=label):
                res = _run_reinstall_setup(self.reinstall, env=env)
                self.assertNotEqual(res.returncode, 0, f'{label} 应被拒绝，却通过: {res.stdout}')
        res = _run_reinstall_setup(self.reinstall, env={'PORT': '2222', 'SWAP_MB': '0', 'RELEASE': '13'})
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_network_validators_exist_and_filter_malformed_values_in_both_scripts(self):
        """两份脚本都应提供 valid_iface / valid_ipv4 / valid_cidr，精准拦截畸形网络参数。"""
        for label, src in (('alpine2debian.sh', self.alpine), ('reinstall-debian13.sh', self.reinstall)):
            fn_iface = _extract_fn(src, 'valid_iface')
            fn_ipv4 = _extract_fn(src, 'valid_ipv4')
            fn_cidr = _extract_fn(src, 'valid_cidr')
            helpers = f'{fn_iface}\n{fn_ipv4}\n{fn_cidr}\n'

            for bad_if in ('', '-eth0', '.', '..', 'eth0/1', 'eth0;id', 'a' * 16):
                with self.subTest(script=label, bad_iface=bad_if):
                    p = subprocess.run([self.sh, '-c', helpers + 'valid_iface "$1" && echo OK || echo BAD', '_', bad_if],
                                       capture_output=True, text=True, timeout=15)
                    self.assertEqual(p.stdout.strip(), 'BAD')
            for good_if in ('eth0', 'ens3', 'enp1s0', 'eth0.100', 'eth0:1', 'br-lan'):
                with self.subTest(script=label, good_iface=good_if):
                    p = subprocess.run([self.sh, '-c', helpers + 'valid_iface "$1" && echo OK || echo BAD', '_', good_if],
                                       capture_output=True, text=True, timeout=15)
                    self.assertEqual(p.stdout.strip(), 'OK')

            for bad_ip in ('', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '-1.2.3.4', '1.2.3.4;id', '1.2.3.999999999999999'):
                with self.subTest(script=label, bad_ip=bad_ip):
                    p = subprocess.run([self.sh, '-c', helpers + 'valid_ipv4 "$1" && echo OK || echo BAD', '_', bad_ip],
                                       capture_output=True, text=True, timeout=15)
                    self.assertEqual(p.stdout.strip(), 'BAD')
            for good_ip in ('0.0.0.0', '10.0.0.1', '192.168.1.254', '255.255.255.255'):
                with self.subTest(script=label, good_ip=good_ip):
                    p = subprocess.run([self.sh, '-c', helpers + 'valid_ipv4 "$1" && echo OK || echo BAD', '_', good_ip],
                                       capture_output=True, text=True, timeout=15)
                    self.assertEqual(p.stdout.strip(), 'OK')

            for bad_cidr in ('', '0', '08', '33', '-24', '24;id', '999999999999999'):
                with self.subTest(script=label, bad_cidr=bad_cidr):
                    p = subprocess.run([self.sh, '-c', helpers + 'valid_cidr "$1" && echo OK || echo BAD', '_', bad_cidr],
                                       capture_output=True, text=True, timeout=15)
                    self.assertEqual(p.stdout.strip(), 'BAD')
            for good_cidr in ('1', '8', '24', '32'):
                with self.subTest(script=label, good_cidr=good_cidr):
                    p = subprocess.run([self.sh, '-c', helpers + 'valid_cidr "$1" && echo OK || echo BAD', '_', good_cidr],
                                       capture_output=True, text=True, timeout=15)
                    self.assertEqual(p.stdout.strip(), 'OK')

            # 校验第 3 步确实在提取后调用了这三个校验函数
            step3_idx = src.index('第 3/')
            step4_idx = src.index('第 4/')
            step3 = src[step3_idx:step4_idx]
            self.assertIn('valid_iface "$MAIN_IFACE"', step3)
            self.assertIn('valid_ipv4 "$MAIN_IP"', step3)
            self.assertIn('valid_ipv4 "$MAIN_GATE"', step3)
            self.assertIn('valid_cidr ', step3)

    def test_alpine_validates_dns_host_and_unlinks_chroot_temp_files_before_write(self):
        """alpine2debian.sh 必须拦截以 - 开头或畸形的 DNS_HOST，且写 chroot 临时文件前先 rm -f 防符号链接。"""
        step2 = self.alpine[self.alpine.index('DNS_HOST='):self.alpine.index('# ── 第 3 步')]
        self.assertRegex(step2, r'case\s+"\$DNS_HOST"\s+in')
        self.assertIn('-*', step2)

        chroot_block = self.alpine[self.alpine.index('# ── 第 7 步：chroot 配置'):self.alpine.index('# ── 第 8 步：网络配置')]
        rm_before = chroot_block.index('rm -f "$MOUNT_DIR/tmp/_setup.sh" "$MOUNT_DIR/tmp/_rootpw"')
        write_setup = chroot_block.index('> "$MOUNT_DIR/tmp/_setup.sh"')
        self.assertLess(rm_before, write_setup, '写 _setup.sh / _rootpw 前应先 rm -f 清理潜在符号链接')

    def test_reinstall_init_log_refuses_symlink_and_size_check_enforces_upper_bound(self):
        """reinstall-debian13.sh 的 init_log/log_line 必须拒绝符号链接，二次体积校验需对齐上限与防符号链接。"""
        fn_init = _extract_fn(self.reinstall, 'init_log')
        fn_line = _extract_fn(self.reinstall, 'log_line')
        self.assertIn('-L "$LOG"', fn_init)
        self.assertIn('-L "$LOG"', fn_line)

        with tempfile.TemporaryDirectory() as td:
            victim = Path(td) / 'victim.txt'
            victim.write_text('KEEP_ME', encoding='utf-8')
            link = Path(td) / 'evil.log'
            try:
                os.symlink(victim, link)
            except (OSError, NotImplementedError):
                # Windows 非提权环境无 symlink 权限时，至少用源码逻辑配合假测试确认降级行为
                pass
            else:
                lp = _to_unix_path(self.sh, link)
                cmd = f'LOG="{lp}"\n{fn_init}\n{fn_line}\ninit_log\nlog_line "pwn"\nprintf "LOG=%s" "$LOG"'
                proc = subprocess.run([self.sh, '-c', cmd], capture_output=True, text=True, timeout=15)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout.strip(), 'LOG=', 'LOG 为符号链接时 init_log 必须置空降级')
                self.assertEqual(victim.read_text(encoding='utf-8'), 'KEEP_ME', '绝不能透过符号链接覆写目标文件')

        step6 = self.reinstall[self.reinstall.index('# 校验下载完整性'):self.reinstall.index('# 组装参数')]
        self.assertIn('2097152', step6)
        self.assertIn('-L "$IN_FILE"', step6)


if __name__ == '__main__':
    unittest.main()
