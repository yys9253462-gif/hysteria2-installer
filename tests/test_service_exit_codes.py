"""install.sh 的服务命令退出码（2026-11-06 修）。

- 未知 / 拼错的子命令报错并以 2 退出，不再进菜单、无终端时以 0 退出；
- 菜单 9（启动）在核心启动后立即退出时报失败，而不是「已启动」；
- `status` 未安装时返回非 0。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
DISPATCH_RE = re.compile(r'^if \[\[ \$# -gt 0 \]\]; then\n.*?^    esac\n(    case "\$1" in\n.*?^    esac\n)',
                         re.S | re.M)


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class ServiceCommandExitCodeTests(unittest.TestCase):
    def run_sh(self, script):
        return subprocess.run([BASH, '-c', script], input='', capture_output=True,
                              text=True, encoding='utf-8', timeout=30)

    def test_unknown_subcommand_exits_2(self):
        # 整个脚本要 root；只摘出主分派的 case 段执行（menu 打桩成旧行为：以 0 退出）
        dispatch = DISPATCH_RE.search(SRC).group(1)
        script = '\n'.join(['log_err() { echo "ERR $*"; }', 'menu() { echo MENU; exit 0; }',
                            'f() {', dispatch, '}', 'f restat'])
        r = self.run_sh(script)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn('未知命令', r.stdout)
        self.assertNotIn('MENU', r.stdout)

    def test_start_reports_failure_when_core_dies(self):
        script = '\n'.join([
            'log_step() { :; }', 'log_info() { echo "INFO $*"; }', 'log_err() { echo "ERR $*"; }',
            'require_installed() { :; }', 'refuse_if_suspended() { :; }', 'sleep() { :; }',
            'journalctl() { :; }',
            'systemctl() { [[ "$1" == is-active ]] && return 3; return 0; }',
            fn('start_service'), 'start_service; echo "RC=$?"'])
        out = self.run_sh(script).stdout
        self.assertIn('RC=1', out)
        self.assertNotIn('已启动', out)

    def test_stop_reports_failure_when_service_stays_up(self):
        script = '\n'.join([
            'log_step() { :; }', 'log_info() { echo "INFO $*"; }', 'log_err() { echo "ERR $*"; }',
            'require_installed() { :; }',
            'systemctl() { [[ "$1" == stop ]] && return 1; [[ "$1" == is-active ]] && return 0; return 0; }',
            fn('stop_service'), 'stop_service; echo "RC=$?"'])
        out = self.run_sh(script).stdout
        self.assertIn('RC=1', out)
        self.assertNotIn('已停止', out)

    def test_status_when_not_installed_is_nonzero(self):
        script = '\n'.join(['HY2_BIN=/nonexistent/hysteria', 'log_err() { :; }',
                            fn('status_service'), 'status_service; echo "RC=$?"'])
        self.assertIn('RC=1', self.run_sh(script).stdout)

    def test_status_is_nonzero_when_core_or_portal_is_down(self):
        """服务停着 / 失败时也返回非零，门户（Hy2 鉴权后端）一起看（2026-11-13 修）。"""
        for down, expected in (('', 'RC=0'), ('hysteria-server', 'RC=1'), ('hysteria-portal', 'RC=1')):
            with self.subTest(down=down or 'none'):
                script = '\n'.join([
                    'HY2_BIN=/bin/sh', 'log_err() { :; }', 'CYAN=; PLAIN=',
                    # systemctl status：在运行返回 0，不在运行返回 3（与真实 systemctl 一致）
                    'systemctl() { echo "STATUS $2"; [[ "$2" == "%s" ]] && return 3; return 0; }' % down,
                    fn('status_service'), 'status_service; echo "RC=$?"'])
                out = self.run_sh(script).stdout
                self.assertIn(expected, out)
                self.assertIn('STATUS hysteria-portal', out)


if __name__ == '__main__':
    unittest.main()
