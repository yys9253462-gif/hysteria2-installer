"""卸载时 AmneziaWG 移除失败，不能删掉控制工具还报「已卸载」（2026-11-03 修）。

hy2-awgctl uninstall 在服务停不下来 / 禁用失败时刻意保留全部资产并退出非零。
旧实现 `… || true` 吞掉退出码、删掉控制工具、照报成功：AWG 仍在运行，
却没了管理它的工具。这里只执行 uninstall_all 里 AWG 那一段。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


def awg_block():
    m = re.search(r'\n(        if \[\[ "\$awg_confirm" =~ \^\[Yy\]\$ \]\]; then\n.*?\n        fi\n)', SRC, re.S)
    return m.group(1)


@unittest.skipUnless(BASH, 'requires bash')
class UninstallAwgFailureTests(unittest.TestCase):
    def run_block(self, ctl_exit):
        with tempfile.TemporaryDirectory() as td:
            ctl = Path(td) / 'hy2-awgctl'
            ctl.write_text('#!/bin/sh\necho "cannot stop amneziawg-server" >&2\nexit %d\n' % ctl_exit,
                           encoding='utf-8')
            ctl.chmod(0o755)
            script = '\n'.join([
                'log_step() { echo "STEP $*"; }', 'log_info() { echo "INFO $*"; }',
                'log_err() { echo "ERR $*"; }', 'awg_ensure_ctl() { :; }',
                'AWG_CTL_BIN="%s"' % bash_path(ctl), 'awg_confirm=y',
                'f() {', awg_block(), '}', 'f', 'test -e "$AWG_CTL_BIN" && echo CTL_KEPT || echo CTL_GONE'])
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True, encoding='utf-8', timeout=20).stdout

    def test_failed_awg_removal_keeps_tool_and_reports_failure(self):
        out = self.run_block(1)
        self.assertIn('CTL_KEPT', out)
        self.assertNotIn('INFO AmneziaWG 已卸载', out)
        self.assertIn('ERR AmneziaWG 卸载失败', out)

    def test_successful_removal_deletes_tool(self):
        out = self.run_block(0)
        self.assertIn('CTL_GONE', out)
        self.assertIn('INFO AmneziaWG 已卸载', out)


if __name__ == '__main__':
    unittest.main()
