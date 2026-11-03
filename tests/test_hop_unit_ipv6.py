"""端口跳跃的开机自愈单元要同时恢复 IPv6 规则（2026-11-03 修）。

安装时 ip6tables 也加了 PREROUTING / OUTPUT 跳跃规则，但 hy2-iptables.service
只恢复 IPv4：没有 netfilter-persistent 的机器重启后，IPv6 客户端的端口跳跃全部超时。
这里渲染真实单元文件，再用假的 iptables / ip6tables 执行它的每条 ExecStart。
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


@unittest.skipUnless(BASH, 'requires bash')
class HopUnitIpv6Tests(unittest.TestCase):
    def test_boot_restore_covers_both_families(self):
        m = re.search(r"cat > /etc/systemd/system/hy2-iptables.service <<EOF\n(.*?)\nEOF\n", SRC, re.S)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fake = td / 'bin'
            fake.mkdir()
            log = td / 'calls'
            for name in ('iptables', 'ip6tables'):
                # -C 一律报「规则不存在」，于是每条都会走 -A。
                (fake / name).write_text('#!/bin/sh\necho "%s $*" >> "%s"\ncase "$*" in *" -C "*) exit 1;; esac\nexit 0\n'
                                         % (name, bash_path(log)), encoding='utf-8')
                (fake / name).chmod(0o755)
            render = 's_port=20000 e_port=40000 l_port=443\ncat <<EOF\n%s\nEOF\n' % m.group(1)
            unit = subprocess.run([BASH, '-c', render], capture_output=True, text=True,
                                  encoding='utf-8').stdout
            starts = [line[len('ExecStart='):] for line in unit.splitlines() if line.startswith('ExecStart=')]
            self.assertTrue(starts)
            for cmd in starts:
                inner = re.fullmatch(r'/bin/bash -c "(.*)"', cmd).group(1)
                subprocess.run([BASH, '-c', 'PATH="%s:$PATH"; %s' % (bash_path(fake), inner)],
                               capture_output=True, text=True, timeout=20)
            calls = log.read_text(encoding='utf-8')
            for family in ('iptables', 'ip6tables'):
                for chain in ('PREROUTING', 'OUTPUT'):
                    self.assertRegex(calls, r'(?m)^%s -t nat -A %s -p udp --dport 20000:40000 ' % (family, chain),
                                     '%s %s 没有在开机时恢复' % (family, chain))


if __name__ == '__main__':
    unittest.main()
