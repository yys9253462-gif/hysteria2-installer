"""iptables 在、nat 表却用不了时跳过端口跳跃，而不是中止安装（2026-11-12 修）。

OpenVZ / 部分 LXC 容器里 `iptables -t nat ...` 报 can't initialize table；旧实现在 set -e 下
直接退出，安装停在「二进制与证书已就位、配置与门户还没写」，重跑每次都卡在同一步。
执行真实的 setup_iptables_port_hopping，iptables 打桩；与 install.sh 一样开 set -eo pipefail。
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

NAT_UNAVAILABLE = 'iptables() { echo "iptables $*" >> %(t)s/calls; [[ "$1 $2" == "-t nat" ]] && return 3; return 0; }'
OUTPUT_ADD_FAILS = ('iptables() { echo "iptables $*" >> %(t)s/calls; case "$*" in *"-A OUTPUT"*) return 1;; esac; '
                    'return 0; }')
WORKING = 'iptables() { echo "iptables $*" >> %(t)s/calls; return 0; }'


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class HopNatUnavailableTests(unittest.TestCase):
    def run_hop(self, iptables_stub, owned_unit=False):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            unit = t / 'hy2-iptables.service'
            if owned_unit:
                unit.write_text('old unit\n', encoding='utf-8')
            body = fn('setup_iptables_port_hopping').replace('/etc/systemd/system/hy2-iptables.service', str(unit))
            script = '\n'.join([
                'set -eo pipefail',
                'log_step() { :; }', 'log_info() { :; }', 'log_err() { echo "ERR $*"; }',
                'log_warn() { echo "WARN $*"; }',
                'clear_all_hopping_rules() { echo clear >> %s/clears; }' % t,
                '_hy2_iptables_unit_owned() { [[ -f %s ]]; }' % unit,
                'systemctl() { echo "systemctl $*" >> %s/calls; }' % t,
                'ip6tables() { echo "ip6tables $*" >> %s/calls; }' % t,
                iptables_stub % {'t': t},
                'command() { if [[ "$1" == -v ]]; then case "$2" in iptables|ip6tables) return 0;; *) return 1;; esac; fi; '
                'builtin command "$@"; }',
                'HOP_START=20000 HOP_END=40000 HOP_PORT_RANGE=20000-40000',
                body,
                'setup_iptables_port_hopping 443 20000 40000',
                'echo "RC=$? RANGE=[$HOP_PORT_RANGE] START=[$HOP_START] END=[$HOP_END]"',
            ])
            r = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20)
            calls = (t / 'calls').read_text() if (t / 'calls').exists() else ''
            clears = len((t / 'clears').read_text().split()) if (t / 'clears').exists() else 0
            unit_text = unit.read_text() if unit.exists() else None
        return r, calls, clears, unit_text

    def test_missing_nat_table_skips_hopping_and_keeps_installing(self):
        r, calls, _, unit_text = self.run_hop(NAT_UNAVAILABLE)
        self.assertIn('RC=0 RANGE=[] START=[] END=[]', r.stdout, r.stdout + r.stderr)
        self.assertIn('nat 表不可用', r.stdout)
        self.assertNotIn('-A PREROUTING', calls)
        self.assertIsNone(unit_text, 'boot unit written although no rule can be restored')

    def test_missing_nat_table_retires_our_old_boot_unit(self):
        r, calls, _, unit_text = self.run_hop(NAT_UNAVAILABLE, owned_unit=True)
        self.assertIn('RC=0 RANGE=[]', r.stdout, r.stdout + r.stderr)
        self.assertIsNone(unit_text, 'old hy2-iptables.service left to fail on every boot')
        self.assertIn('systemctl disable --now hy2-iptables.service', calls)

    def test_failed_rule_add_cleans_up_and_skips(self):
        r, calls, clears, unit_text = self.run_hop(OUTPUT_ADD_FAILS)
        self.assertIn('RC=0 RANGE=[] START=[] END=[]', r.stdout, r.stdout + r.stderr)
        self.assertIn('添加 nat 转发规则失败', r.stdout)
        self.assertEqual(clears, 2, 'the PREROUTING rule that did get added was not removed again')
        self.assertIsNone(unit_text)

    def test_working_nat_keeps_the_range_and_writes_the_unit(self):
        r, calls, _, unit_text = self.run_hop(WORKING)
        self.assertIn('RC=0 RANGE=[20000-40000] START=[20000] END=[40000]', r.stdout, r.stdout + r.stderr)
        self.assertIn('-A PREROUTING', calls)
        self.assertIn('--dport 20000:40000', unit_text or '')


if __name__ == '__main__':
    unittest.main()
