"""流量超额停用期间，终端菜单不能拉起 AmneziaWG（2026-11-12 修）。

门户的 AWG 端点在停用期间拒绝 set_line / update / start / restart，install.sh 的 Hy2 启动、
WARP、gost 菜单也会拒绝；唯独 AWG 的安装、更新、切协议线与「重新同步」没拦 —— 它们结尾
都会 systemctl restart amneziawg-server，停用就形同虚设。执行真实函数，hy2-awgctl 用桩记录调用。
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
DISPATCH_RE = re.compile(r'^if \[\[ \$# -gt 0 \]\]; then\n.*?^    esac\n(    case "\$1" in\n.*?^    esac\n)',
                         re.S | re.M)

STUBS = r'''
log_warn() { echo "WARN $*"; }; log_err() { echo "ERR $*"; }; log_info() { :; }; log_step() { :; }
check_root() { :; }; check_arch() { :; }; clear() { :; }; get_public_ip() { :; }; install_dependencies() { :; }
awg_ensure_ctl() { return 0; }; awg_is_installed() { return 0; }
awg_current_line() { echo 3; }; awg_suggest_endpoint() { echo vpn.example.com; }
traffic_suspended() { return 0; }
AWG_PEERS_FILE=/nonexistent/awg_peers.json; AWG_PORT_MIN=50000; AWG_PORT_MAX=59000
AWG_CTL_BIN=awgctl_stub
awgctl_stub() { echo "CTL $*"; }
'''


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class AwgMenuSuspendTests(unittest.TestCase):
    def run_sh(self, call, stdin=''):
        script = '\n'.join([STUBS, fn('refuse_if_suspended'), fn('install_amneziawg'), fn('update_amneziawg'),
                            fn('awg_menu_switch_line'), fn('menu_amneziawg'), call])
        return subprocess.run([BASH, '-c', script], input=stdin, capture_output=True, text=True,
                              encoding='utf-8', timeout=30).stdout

    def test_awg_actions_that_restart_the_service_are_refused_while_suspended(self):
        for name, call, stdin in (('install', 'install_amneziawg', '\n\n\n\n'),
                                  ('update', 'update_amneziawg', ''),
                                  ('switch line', 'awg_menu_switch_line', 'y\n'),
                                  ('menu resync', 'menu_amneziawg', '7\n\n0\n')):
            with self.subTest(name=name):
                out = self.run_sh(call, stdin)
                self.assertNotRegex(out, r'CTL (install|update|resync)\b', out)
                self.assertIn('流量超额', out)

    def test_cli_passthrough_is_refused_while_suspended(self):
        """`install.sh awg-install …` 与 `install.sh awg update|resync|install` 直接 exec 透传，同样要拦。"""
        dispatch = DISPATCH_RE.search(SRC).group(1)
        with tempfile.TemporaryDirectory() as d:
            ctl = Path(d) / 'hy2-awgctl'
            ctl.write_bytes(b'#!/bin/sh\necho "CTL $*"\n')
            ctl.chmod(0o755)
            for args in ('awg-install --line 3 --endpoint vpn.example.com', 'awg update', 'awg resync'):
                with self.subTest(args=args):
                    out = self.run_sh('AWG_CTL_BIN=%s\nf() {\n%s}\nf %s' % (ctl, dispatch, args))
                    self.assertNotRegex(out, r'CTL (install|update|resync)\b', out)
                    self.assertIn('流量超额', out)
            out = self.run_sh('AWG_CTL_BIN=%s\nf() {\n%s}\nf awg peer-list' % (ctl, dispatch))
            self.assertIn('CTL peer-list', out, 'read-only passthrough must keep working while suspended')


if __name__ == '__main__':
    unittest.main()
