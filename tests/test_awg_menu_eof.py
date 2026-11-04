"""AWG 菜单在 EOF 时干净退出，不被 set -e 静默杀掉，也不空转（2026-11-04 修）。

执行 install.sh 里真实的 menu_amneziawg / awg_menu_del_peer，stdin 直接为空。
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
class AwgMenuEofTests(unittest.TestCase):
    def run_fn(self, name, extra=''):
        script = '\n'.join([
            'set -eo pipefail', 'RED= GREEN= YELLOW= BLUE= CYAN= PLAIN=',
            'log_err() { :; }', 'log_info() { :; }', 'log_warn() { :; }', 'log_step() { :; }',
            'clear() { :; }', 'awg_is_installed() { return 0; }', 'awg_ensure_ctl() { :; }', 'check_root() { :; }',
            'AWG_CTL_BIN=true', extra, fn(name), '%s; echo "RC=$?"' % name])
        return subprocess.run([BASH, '-c', script], input='', capture_output=True,
                              text=True, timeout=15)

    def test_menu_returns_on_eof(self):
        r = self.run_fn('menu_amneziawg', 'awg_status_line() { :; }')
        self.assertIn('RC=0', r.stdout)

    def test_delete_prompt_survives_eof(self):
        # set -e 下 `f; echo` 里 f 返回 1 会终止脚本，这里用 || 接住，看函数自己的返回值。
        script_fn = 'awg_menu_del_peer'
        script = '\n'.join([
            'set -eo pipefail', 'log_err() { echo "ERR $*"; }', 'log_info() { :; }',
            'check_root() { :; }', 'awg_ensure_ctl() { :; }',
            'AWG_CTL_BIN=true', fn(script_fn), '%s || echo "RC=$?"' % script_fn])
        r = subprocess.run([BASH, '-c', script], input='', capture_output=True, text=True, timeout=15)
        self.assertIn('ERR 名称不能为空', r.stdout)
        self.assertIn('RC=1', r.stdout)


if __name__ == '__main__':
    unittest.main()
