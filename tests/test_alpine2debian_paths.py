"""alpine2debian.sh 的若干失败路径（2026-11-04 修）。

整个脚本需要 root、Alpine 救援环境与真磁盘；这里摘出真实片段在 sh 里执行。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'alpine2debian.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
SH = shutil.which('sh') or shutil.which('bash')


def run(script, stdin=''):
    return subprocess.run([SH, '-c', script], input=stdin, capture_output=True, text=True, timeout=20)


def arg_loop():
    start = SRC.index('while [ $# -gt 0 ]; do')
    return SRC[start:SRC.index('\ndone\n', start) + 6]


@unittest.skipUnless(SH, 'requires sh')
class Alpine2DebianTests(unittest.TestCase):
    PRE = 'die() { echo "DIE $*"; exit 1; }\nusage() { :; }\n'

    def test_option_without_value_gets_a_clear_error(self):
        for opt in ('--disk', '--mirror', '--suite', '--pwd'):
            with self.subTest(opt=opt):
                r = run(self.PRE + 'set -- %s\n' % opt + arg_loop())
                self.assertIn('DIE %s 缺少取值' % opt, r.stdout)

    def test_option_with_value_is_parsed(self):
        r = run(self.PRE + 'set -- --disk /dev/vdb\n' + arg_loop() + 'echo "D=$DISK"')
        self.assertIn('D=/dev/vdb', r.stdout)

    def test_password_prompt_eof_reports_empty_password(self):
        start = SRC.index('    if [ -t 0 ]; then read -r ROOT_PWD')
        line = SRC[start:SRC.index('\n', start)]
        script = ('set -eu\n' + self.PRE + 'ROOT_PWD=""\n' + line.strip()
                  + '\n[ -n "$ROOT_PWD" ] || die "root 密码不能为空"\n')
        r = run(script.replace('</dev/tty', '</dev/null'))
        self.assertIn('DIE root 密码不能为空', r.stdout)

    def test_partition_hint_does_not_execute_partx(self):
        start = SRC.index('[ -b "$ROOT_PART" ] || die "分区设备')
        end = SRC.index('"\n', SRC.index('重跑本脚本', start)) + 1
        with tempfile.TemporaryDirectory() as td:
            script = ('partx() { echo RAN > %s/ran; }\n' % td + self.PRE
                      + 'ROOT_PART=/nonexistent DISK=/dev/x\n' + SRC[start:end])
            r = run(script)
            self.assertFalse((Path(td) / 'ran').exists(), '报错信息里的 partx 被执行了')
        self.assertIn('partx -a -n 1:1 /dev/x', r.stdout)

    def _net_stanza(self, addr_line):
        start = SRC.index('if ip -4 addr show "$MAIN_IFACE" 2>/dev/null | grep \'inet \' | grep -q dynamic; then')
        end = SRC.index('\nfi\n', start) + 4
        script = ('warn() { :; }\nip() { echo "    inet %s"; }\n' % addr_line
                  + 'MAIN_IFACE=eth0 MAIN_IP=203.0.113.5 MAIN_CIDR=24 MAIN_GATE=203.0.113.1\n'
                  + SRC[start:end] + 'printf "%s" "$NET_STANZA"')
        return run(script).stdout

    def test_static_address_is_written_as_static(self):
        out = self._net_stanza('203.0.113.5/24 brd 203.0.113.255 scope global eth0')
        self.assertIn('inet static', out)
        self.assertIn('address 203.0.113.5/24', out)
        self.assertIn('gateway 203.0.113.1', out)

    def test_dhcp_address_stays_dhcp(self):
        out = self._net_stanza('203.0.113.5/24 brd 203.0.113.255 scope global dynamic eth0')
        self.assertIn('inet dhcp', out)

    def test_default_route_check_reads_output_not_exit_code(self):
        """ip route 没有默认路由时也返回 0；判定必须看输出。"""
        start = SRC.index('if [ -z "$(ip route show default 2>/dev/null)" ]; then')
        end = SRC.index('\nfi\n', start) + 4
        r = run(self.PRE + 'ip() { :; }\n' + SRC[start:end])
        self.assertIn('DIE 仍然没有默认路由', r.stdout)


if __name__ == '__main__':
    unittest.main()
