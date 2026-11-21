"""回归测试：install.sh 核心操作锁文件描述符与排他锁必须在所有退出路径释放。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')
FLOCK = shutil.which('flock')


def _extract_fn(source: str, name: str) -> str:
    match = re.search(rf'^{name}\(\) \{{\n.*?^\}}', source, re.S | re.M)
    if not match:
        raise AssertionError(f'install.sh 中未找到函数 {name}')
    return match.group(0)


@unittest.skipUnless(BASH, '需要 bash 环境')
class InstallerCoreLockReleaseTests(unittest.TestCase):
    def _run_bash(self, script: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [BASH, '-c', script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            env=env,
            timeout=20,
        )

    def test_acquire_failure_and_release_do_not_leak_file_descriptors(self):
        """拿锁失败与正常释放后，当前进程打开的文件描述符数量不得增长。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        acq = _extract_fn(src, 'acquire_installer_core_lock')
        rel = _extract_fn(src, 'release_installer_core_lock')
        with tempfile.TemporaryDirectory() as td:
            td_posix = Path(td).as_posix()
            script = '\n'.join([
                'set -uo pipefail',
                f'HY2_DIR="{td_posix}"',
                'log_err() { :; }; log_warn() { :; }; log_info() { :; }',
                'count_fds() { local c=0 p; for p in /proc/$$/fd/*; do [[ -e "$p" ]] && c=$((c+1)); done; echo "$c"; }',
                acq,
                rel,
                'base="$(count_fds)"',
                'flock() { return 1; }',
                'for i in 1 2 3 4 5; do acquire_installer_core_lock && exit 91; done',
                'after_fail="$(count_fds)"',
                'flock() { return 0; }',
                'acquire_installer_core_lock || exit 92',
                'during_lock="$(count_fds)"',
                'release_installer_core_lock',
                'after_rel="$(count_fds)"',
                'echo "BASE=$base FAIL=$after_fail LOCK=$during_lock REL=$after_rel"',
            ])
            res = self._run_bash(script)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            vals = dict(item.split('=', 1) for item in res.stdout.strip().splitlines()[-1].split())
            self.assertEqual(vals['FAIL'], vals['BASE'], f'拿锁失败泄漏了文件描述符: {vals}')
            self.assertEqual(vals['REL'], vals['BASE'], f'释放锁后仍残留打开的描述符: {vals}')

    def test_flow_update_core_closes_lock_fd_on_all_exit_paths(self):
        """flow_update_core 无论拒更、失败还是成功退出，都必须关闭核心锁描述符。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        upd = _extract_fn(src, 'flow_update_core')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            hy2_bin = td_path / 'hysteria'
            hy2_bin.write_text('#!/usr/bin/env bash\necho "Version: v2.6.0"\n', encoding='utf-8', newline='\n')
            td_posix = td_path.as_posix()
            bin_posix = hy2_bin.as_posix()
            script = '\n'.join([
                'set -uo pipefail',
                f'HY2_DIR="{td_posix}"',
                f'HY2_BIN="{bin_posix}"',
                'log_err() { :; }; log_warn() { :; }; log_info() { :; }',
                'check_root() { return 0; }',
                'check_arch() { return 0; }',
                'require_installed() { return 0; }',
                'traffic_suspended() { return 1; }',
                'install_binary() { return 0; }',
                'restart_service() { return 0; }',
                'count_fds() { local c=0 p; for p in /proc/$$/fd/*; do [[ -e "$p" ]] && c=$((c+1)); done; echo "$c"; }',
                upd,
                'base="$(count_fds)"',
                # 场景 1：flock 被占用失败
                'flock() { return 1; }',
                'flow_update_core && exit 81',
                'fd_busy="$(count_fds)"',
                # 场景 2：定制核心被拒绝更新
                'flock() { return 0; }',
                f'printf "#!/usr/bin/env bash\\necho \\"Version: v2.6.0+teyir\\"\\n" > "{bin_posix}"; chmod +x "{bin_posix}"',
                'flow_update_core && exit 82',
                'fd_custom="$(count_fds)"',
                # 场景 3：正常完成更新
                f'printf "#!/usr/bin/env bash\\necho \\"Version: v2.6.0\\"\\n" > "{bin_posix}"; chmod +x "{bin_posix}"',
                'flow_update_core || exit 83',
                'fd_ok="$(count_fds)"',
                'echo "BASE=$base BUSY=$fd_busy CUSTOM=$fd_custom OK=$fd_ok"',
            ])
            res = self._run_bash(script)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            vals = dict(item.split('=', 1) for item in res.stdout.strip().splitlines()[-1].split())
            self.assertEqual(vals['BUSY'], vals['BASE'], f'锁冲突退出泄漏描述符: {vals}')
            self.assertEqual(vals['CUSTOM'], vals['BASE'], f'定制核心拒更退出泄漏描述符: {vals}')
            self.assertEqual(vals['OK'], vals['BASE'], f'正常完成更新后仍泄漏描述符: {vals}')

    @unittest.skipUnless(FLOCK, '需要真实 flock 命令验证跨进程锁释放')
    def test_real_flock_is_released_after_flow_update_core_and_release_helper(self):
        """使用真实 flock 验证操作完成后外部进程可立即抢占 .core-operation.lock。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        acq = _extract_fn(src, 'acquire_installer_core_lock')
        rel = _extract_fn(src, 'release_installer_core_lock')
        upd = _extract_fn(src, 'flow_update_core')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            hy2_bin = td_path / 'hysteria'
            hy2_bin.write_text('#!/usr/bin/env bash\necho "Version: v2.6.0"\n', encoding='utf-8', newline='\n')
            os.chmod(hy2_bin, 0o755)
            td_posix = td_path.as_posix()
            bin_posix = hy2_bin.as_posix()
            script = '\n'.join([
                'set -euo pipefail',
                f'HY2_DIR="{td_posix}"',
                f'HY2_BIN="{bin_posix}"',
                'log_err() { :; }; log_warn() { :; }; log_info() { :; }',
                'check_root() { return 0; }',
                'check_arch() { return 0; }',
                'require_installed() { return 0; }',
                'traffic_suspended() { return 1; }',
                'install_binary() { return 0; }',
                'restart_service() { return 0; }',
                acq,
                rel,
                upd,
                'acquire_installer_core_lock',
                'if flock -n "$HY2_DIR/.core-operation.lock" true; then echo "STILL_UNLOCKED"; exit 71; fi',
                'release_installer_core_lock',
                'flock -n "$HY2_DIR/.core-operation.lock" true',
                'flow_update_core',
                'flock -n "$HY2_DIR/.core-operation.lock" true',
                'echo "ALL_RELEASED"',
            ])
            res = self._run_bash(script)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('ALL_RELEASED', res.stdout)


if __name__ == '__main__':
    unittest.main()
