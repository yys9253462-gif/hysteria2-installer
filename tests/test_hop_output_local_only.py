"""端口跳跃的 OUTPUT 规则只重定向发往本机的 UDP（2026-11-04 修）。

nat OUTPUT 看得到代理替用户发往远端的每个新 UDP 流；不限目的时，用户访问
远端 20000-40000 端口（游戏服、WebRTC、VoIP）全部被 REDIRECT 到本机监听口。
执行真实的 setup_iptables_port_hopping，iptables 打桩记录参数；开机恢复单元同样检查。
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


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class HopOutputLocalOnlyTests(unittest.TestCase):
    def test_output_rules_match_local_destinations_only(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            unit = t / 'hy2-iptables.service'
            body = fn('setup_iptables_port_hopping').replace('/etc/systemd/system/hy2-iptables.service', str(unit))
            script = '\n'.join([
                'log_step() { :; }', 'log_info() { :; }', 'log_warn() { :; }', 'log_err() { :; }',
                'clear_all_hopping_rules() { :; }', '_hy2_iptables_unit_owned() { return 0; }',
                'systemctl() { :; }',
                'iptables() { echo "iptables $*" >> %s/calls; }' % t,
                'ip6tables() { echo "ip6tables $*" >> %s/calls; }' % t,
                'command() { if [[ "$1" == -v ]]; then case "$2" in iptables|ip6tables) return 0;; *) return 1;; esac; fi; builtin command "$@"; }',
                body, 'setup_iptables_port_hopping 443 20000 40000'])
            subprocess.run([BASH, '-c', script], check=True, timeout=20)
            calls = (t / 'calls').read_text().splitlines()
            unit_text = unit.read_text()
        output = [c for c in calls if ' OUTPUT ' in c]
        self.assertEqual(len(output), 2, calls)
        for line in output:
            self.assertIn('-m addrtype --dst-type LOCAL', line)
        persisted = re.findall(r'-[AC] OUTPUT [^;|]*', unit_text)
        self.assertEqual(len(persisted), 4, unit_text)
        for line in persisted:
            self.assertIn('-m addrtype --dst-type LOCAL', line)
        for line in calls + persisted:
            if 'PREROUTING' in line:
                self.assertNotIn('addrtype', line)


if __name__ == '__main__':
    unittest.main()
