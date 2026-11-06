"""nftables 放行覆盖所有会拦截的 input 链（2026-11-06 修）。

旧实现只取第一条 `policy drop` 的 input 链：双栈主机上 ip6 链没放行；以「policy accept +
末尾 drop」写的链（nftables.conf 常见写法）被完全跳过。执行真实的 setup_system_firewall，
nft 打桩成返回一份 ruleset 并记录 insert。
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

RULESET = """table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
	}
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
	}
}
table ip6 filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
	}
}
table inet fw {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state established accept
		drop
	}
}
table inet open {
	chain input {
		type filter hook input priority 10; policy accept;
		ct state established accept
	}
}
"""


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class NftAllInputChainsTests(unittest.TestCase):
    def test_every_blocking_input_chain_gets_the_rules(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / 'ruleset').write_text(RULESET)
            script = '\n'.join([
                'log_step() { :; }', 'log_info() { :; }', 'log_warn() { :; }', 'log_err() { echo "ERR $*"; }',
                'HY2_SUB_PORT=18080; CERT_TYPE=self_signed',
                'command() { if [[ "$1" == -v ]]; then [[ "$2" == nft ]]; return; fi; builtin command "$@"; }',
                'systemctl() { return 1; }',
                'nft() { case "$1 $2" in "list ruleset") cat %s/ruleset ;; "list chain") : ;; '
                '"insert rule") echo "INS $3 $4 $5 $6 $8" >> %s/calls ;; esac; return 0; }' % (t, t),
                fn('setup_system_firewall'), 'setup_system_firewall 14617 "" ""; echo "RC=$?"'])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30).stdout
            calls = (t / 'calls').read_text() if (t / 'calls').exists() else ''
        self.assertIn('RC=0', out, out)
        self.assertIn('INS ip filter INPUT udp 14617', calls)
        self.assertIn('INS ip6 filter INPUT udp 14617', calls, 'ip6 的 INPUT 链没有放行')
        self.assertIn('INS inet fw input udp 14617', calls, '末尾 drop 的链没有放行')
        self.assertNotIn('inet open', calls, '不拦截的链不该被改')
        self.assertNotIn('FORWARD', calls)


if __name__ == '__main__':
    unittest.main()
