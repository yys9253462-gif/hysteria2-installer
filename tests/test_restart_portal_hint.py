"""菜单启动 / 重启 Hysteria 后，门户停着要提醒（2026-11-13 修）。

门户是 Hy2 的鉴权后端：它停着时核心重启得再好用户也连不上，旧实现只报「已启动 / 已重启」，
管理员以为问题解决了。提醒不能改变返回值 —— 核心升级靠 restart_service 的返回值决定是否回滚。
执行真实的函数，systemctl 用桩控制两个单元的状态。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')

SYSTEMCTL = r'''
systemctl() {
    if [[ "$1" == is-active ]]; then
        [[ "${@: -1}" == hysteria-portal ]] && { [[ "$PORTAL_UP" == 1 ]]; return; }
        return 0
    fi
    return 0
}
'''


def fn(name):
    m = re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M)
    return m.group(0) if m else ''


@unittest.skipUnless(BASH, 'requires bash')
class RestartPortalHintTests(unittest.TestCase):
    def run_fn(self, name, portal_up, log_warn='log_warn() { echo "WARN $*"; }'):
        script = '\n'.join([
            'PORTAL_UP=%d' % portal_up,
            'log_step() { :; }', 'log_info() { echo "INFO $*"; }', 'log_err() { echo "ERR $*"; }',
            log_warn, 'require_installed() { :; }', 'refuse_if_suspended() { :; }',
            'sleep() { :; }', 'journalctl() { :; }', SYSTEMCTL,
            fn('warn_if_portal_down'), fn(name), '%s; echo "RC=$?"' % name])
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                              encoding='utf-8', timeout=20).stdout

    def test_portal_down_is_reported_after_start_and_restart(self):
        for name, done in (('start_service', 'INFO 已启动'), ('restart_service', 'INFO 已重启')):
            with self.subTest(name=name):
                out = self.run_fn(name, portal_up=0)
                self.assertIn(done, out)
                self.assertIn('RC=0', out)
                warn = '\n'.join(line for line in out.splitlines() if line.startswith('WARN'))
                self.assertIn('门户', warn)
                self.assertIn('菜单 15', warn)
                self.assertIn('systemctl restart hysteria-portal', warn)

    def test_no_hint_when_portal_is_running(self):
        for name in ('start_service', 'restart_service'):
            with self.subTest(name=name):
                out = self.run_fn(name, portal_up=1)
                self.assertIn('RC=0', out)
                self.assertNotIn('WARN', out)

    def test_hint_never_changes_the_return_code(self):
        for name in ('start_service', 'restart_service'):
            with self.subTest(name=name):
                out = self.run_fn(name, portal_up=0, log_warn='log_warn() { return 1; }')
                self.assertIn('RC=0', out)


if __name__ == '__main__':
    unittest.main()
