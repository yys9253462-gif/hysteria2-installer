"""主菜单状态栏按服务的实际状态显示（2026-11-13 修）。

旧实现不是「运行中」就是「已停止」：配置写坏后服务失败、或正在崩溃自动重启，也显示「已停止」，
像是有人把它停了，管理员去点「启动服务」而不是看日志。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


STUB = r'''
GREEN=; RED=; YELLOW=; PLAIN=
systemctl() {
    if [[ "$1" == is-active ]]; then
        [[ "$2" == --quiet ]] || echo "$STATE"
        [[ "$STATE" == active ]]
        return
    fi
    [[ "$1" == list-unit-files && "$LISTED" == 1 ]] && echo "$2 enabled"
    return 0
}
'''


@unittest.skipUnless(shutil.which('bash'), 'requires bash')
class MenuUnitStateTest(unittest.TestCase):
    def state_text(self, state, listed=True):
        script = STUB + fn('unit_state_text') + '\nunit_state_text hysteria-server\n'
        run = subprocess.run([shutil.which('bash'), '-c', script], capture_output=True, text=True,
                             encoding='utf-8', timeout=20,
                             env={'STATE': state, 'LISTED': '1' if listed else '0', 'PATH': '/usr/bin:/bin'})
        return run.stdout.strip().splitlines()[-1]

    def test_each_state_is_named_for_what_it_is(self):
        for state, listed, expected in (('active', True, '运行中'), ('failed', True, '运行失败'),
                                        ('activating', True, '启动中'), ('inactive', True, '已停止'),
                                        ('inactive', False, '未安装')):
            with self.subTest(state=state, listed=listed):
                self.assertIn(expected, self.state_text(state, listed))

    def test_a_failed_service_points_to_the_logs(self):
        self.assertIn('查看日志', self.state_text('failed'))

    def test_awg_line_uses_the_same_wording(self):
        """AWG 那一行此前只分「运行中 / 已安装但未运行」，失败也显示成未运行。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'awg0.conf').write_text('[Interface]\n', encoding='utf-8')
            (root / 'awg-meta.json').write_text('{"port": 51820}', encoding='utf-8')
            (root / 'config.yaml').write_text('auth:\n  type: http\n', encoding='utf-8')
            script = (STUB + 'HY2_BIN=/bin/sh; HY2_CONFIG="$1/config.yaml"; AWG_CONFIG="$1/awg0.conf"; '
                      'AWG_META_FILE="$1/awg-meta.json"; CYAN=; BLUE=\n'
                      'traffic_suspended() { return 1; }; awg_current_line() { echo 3; }\n'
                      + fn('unit_state_text') + '\n' + fn('show_menu_status') + '\nshow_menu_status\n')
            run = subprocess.run([shutil.which('bash'), '-c', script, 'bash', str(root)], capture_output=True,
                                 text=True, encoding='utf-8', timeout=20,
                                 env={'STATE': 'failed', 'LISTED': '1', 'PATH': '/usr/bin:/bin'})
            awg_line = next(line for line in run.stdout.splitlines() if line.startswith('AWG 状态'))
            self.assertIn('运行失败', awg_line)
            self.assertIn('UDP 51820', awg_line)


if __name__ == '__main__':
    unittest.main()
