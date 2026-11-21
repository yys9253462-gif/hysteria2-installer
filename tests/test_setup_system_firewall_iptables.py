"""回归测试：setup_system_firewall 裸 iptables 兜底必须同时放行 ip6tables，并识别 policy ACCEPT + 末尾 DROP/REJECT 规则。"""

import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')


def _extract_setup_firewall() -> str:
    src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
    start = src.index('setup_system_firewall() {\n')
    end = src.index('\n# 重装/改配置前的凭据快照', start)
    return src[start:end]


@unittest.skipUnless(BASH, '需要 bash 环境')
class SetupSystemFirewallIptablesTests(unittest.TestCase):
    def _run_firewall(self, v4_list: str, v6_list: str, cert_type: str = 'self_signed'):
        fn = _extract_setup_firewall()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log_file = root / 'calls.log'
            script = root / 'run_fw.sh'
            script.write_text('\n'.join([
                'set -euo pipefail',
                f'HY2_SUB_PORT=8443',
                f'CERT_TYPE="{cert_type}"',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                'command() {',
                '    if [[ "$1" == "-v" ]]; then',
                '        case "$2" in',
                '            iptables|ip6tables) return 0 ;;',
                '            *) return 1 ;;',
                '        esac',
                '    fi',
                '    builtin command "$@"',
                '}',
                'iptables() {',
                '    if [[ "$1" == "-L" ]]; then',
                f'        printf "%s\\n" {shlex.quote(v4_list)}',
                '        return 0',
                '    fi',
                '    if [[ "$1" == "-C" ]]; then return 1; fi',
                f'    echo "iptables $*" >> "{log_file.as_posix()}"',
                '    return 0',
                '}',
                'ip6tables() {',
                '    if [[ "$1" == "-L" ]]; then',
                f'        printf "%s\\n" {shlex.quote(v6_list)}',
                '        return 0',
                '    fi',
                '    if [[ "$1" == "-C" ]]; then return 1; fi',
                f'    echo "ip6tables $*" >> "{log_file.as_posix()}"',
                '    return 0',
                '}',
                fn,
                'setup_system_firewall 443 20000 40000',
            ]) + '\n', encoding='utf-8', newline='\n')
            res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            return log_file.read_text(encoding='utf-8') if log_file.exists() else ''

    def test_allows_ip6tables_when_ipv6_input_policy_is_drop(self):
        """双栈主机 ip6tables INPUT 默认 DROP 时必须同步放行 IPv6 端口，不能只放 IPv4。"""
        v4 = 'Chain INPUT (policy DROP)\ntarget prot opt source destination\n'
        v6 = 'Chain INPUT (policy DROP)\ntarget prot opt source destination\n'
        calls = self._run_firewall(v4, v6)
        self.assertIn('iptables -I INPUT -p udp --dport 443 -j ACCEPT', calls)
        self.assertIn('ip6tables -I INPUT -p udp --dport 443 -j ACCEPT', calls,
                      '双栈主机漏放行 ip6tables 主端口')
        self.assertIn('ip6tables -I INPUT -p tcp --dport 8443 -j ACCEPT', calls,
                      '双栈主机漏放行 ip6tables 订阅端口')
        self.assertIn('ip6tables -I INPUT -p udp --dport 20000:40000 -j ACCEPT', calls,
                      '双栈主机漏放行 ip6tables 端口跳跃区间')

    def test_allows_ports_when_policy_accept_with_terminal_reject_or_drop_rule(self):
        """policy ACCEPT 但链尾存在 REJECT/DROP 规则时（云镜像常见配置），必须插入放行规则。"""
        v4 = (
            'Chain INPUT (policy ACCEPT)\n'
            'target     prot opt source               destination\n'
            'ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED\n'
            'REJECT     all  --  0.0.0.0/0            0.0.0.0/0            reject-with icmp-host-prohibited\n'
        )
        v6 = (
            'Chain INPUT (policy ACCEPT)\n'
            'target     prot opt source               destination\n'
            'DROP       all      ::/0                 ::/0\n'
        )
        calls = self._run_firewall(v4, v6, cert_type='acme')
        self.assertIn('iptables -I INPUT -p udp --dport 443 -j ACCEPT', calls,
                      'policy ACCEPT + 末尾 REJECT 未放行 IPv4 主端口')
        self.assertIn('iptables -I INPUT -p tcp --dport 80 -j ACCEPT', calls)
        self.assertIn('ip6tables -I INPUT -p udp --dport 443 -j ACCEPT', calls,
                      'policy ACCEPT + 末尾 DROP 未放行 IPv6 主端口')


if __name__ == '__main__':
    unittest.main()
