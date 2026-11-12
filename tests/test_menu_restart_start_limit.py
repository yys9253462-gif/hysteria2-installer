"""菜单的启动 / 重启先清失败计数（2026-11-12 修）。

hysteria-server 单元是 StartLimitBurst=5 / StartLimitIntervalSec=300：配置写坏时每 10 秒崩溃
重启一次，约 50 秒就撞上限。之后修好配置、在菜单里选启动或重启，systemctl 直接拒绝
（start request repeated too quickly），最长 5 分钟内怎么试都失败。门户、核心升级脚本都先
reset-failed，菜单 9 / 11 / 15 没有。执行真实的函数，systemctl 用模拟上限的桩。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')

LIMITED_SYSTEMCTL = r'''
limited=1; started=0
systemctl() {
    case "$1" in
        reset-failed) limited=0 ;;
        start|restart)
            if [[ "$limited" == 1 ]]; then echo "start request repeated too quickly" >&2; return 1; fi
            started=1 ;;
        is-active) [[ "$started" == 1 ]]; return ;;
    esac
    return 0
}
'''


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class MenuRestartStartLimitTests(unittest.TestCase):
    def run_fn(self, name):
        script = '\n'.join([
            'log_step() { :; }', 'log_info() { echo "INFO $*"; }', 'log_err() { echo "ERR $*"; }',
            'require_installed() { :; }', 'refuse_if_suspended() { :; }', 'sleep() { :; }',
            'journalctl() { :; }', 'warn_if_portal_down() { :; }', LIMITED_SYSTEMCTL, fn(name),
            '%s; echo "RC=$?"' % name])
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                              encoding='utf-8', timeout=20).stdout

    def test_menu_actions_get_past_a_hit_start_limit(self):
        for name, done in (('start_service', 'INFO 已启动'), ('restart_service', 'INFO 已重启'),
                           ('restart_portal', 'INFO 已重启')):
            with self.subTest(name=name):
                out = self.run_fn(name)
                self.assertIn('RC=0', out)
                self.assertIn(done, out)


if __name__ == '__main__':
    unittest.main()
