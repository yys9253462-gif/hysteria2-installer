"""菜单 15 重启门户后要确认它还活着（2026-11-04 修）。

hysteria-portal 是 Type=simple：restart 一 fork 就返回成功。门户包半更新、import
失败时旧实现照报「已重启」，而门户是 Hy2 的鉴权后端，所有用户随之连不上。
执行真实的 restart_portal，systemctl 用桩。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class RestartPortalVerifyTests(unittest.TestCase):
    def run_restart(self, alive):
        script = '\n'.join([
            'log_step() { :; }', 'log_info() { echo "INFO $*"; }', 'log_err() { echo "ERR $*"; }',
            'require_installed() { return 0; }', 'sleep() { :; }', 'journalctl() { :; }',
            'systemctl() { case "$1" in restart) return 0;; is-active) return %d;; esac; }' % (0 if alive else 3),
            fn('restart_portal'), 'restart_portal; echo "RC=$?"'])
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                              encoding='utf-8', timeout=20).stdout

    def test_portal_that_exits_after_restart_is_reported(self):
        out = self.run_restart(alive=False)
        self.assertIn('RC=1', out)
        self.assertNotIn('INFO 已重启', out)

    def test_healthy_restart_reports_success(self):
        out = self.run_restart(alive=True)
        self.assertIn('RC=0', out)
        self.assertIn('INFO 已重启', out)


if __name__ == '__main__':
    unittest.main()
