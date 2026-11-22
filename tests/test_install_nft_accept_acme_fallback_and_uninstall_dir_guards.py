"""回归测试：install.sh 的 nftables 区分 drop 与 accept、ACME 签发结果校验与自签失败透传、卸载目录防误删守卫。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


def _bash():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('bash')


def _extract(src: str, name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\) \{{\n.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'未找到函数 {name}()')
    return m.group(0) + '\n'


class InstallNftAcceptAcmeFallbackAndUninstallDirGuardsTests(unittest.TestCase):
    def setUp(self):
        self.bash = _bash()
        if not self.bash:
            self.skipTest('需要 bash 环境')
        self.src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')

    def _run(self, script: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory(prefix='hy2-fw-guard-') as td:
            p = Path(td) / 'run.sh'
            p.write_text('set -eo pipefail\n' + script, encoding='utf-8', newline='\n')
            return subprocess.run(
                [self.bash, str(p)],
                cwd=td,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
            )

    def test_nft_does_not_treat_drop_rule_as_already_allowed(self):
        """链内已有 udp dport 14617 drop 时，setup_system_firewall 仍必须插入 accept 放行规则，不能误判为已放行。"""
        body = (
            """
log_step() { :; }
log_info() { :; }
log_warn() { :; }
log_err() { echo "ERR $*"; }
HY2_SUB_PORT=18080
CERT_TYPE=self_signed
CALLS="./nft_calls.log"
: > "$CALLS"
command() { if [[ "$1" == -v ]]; then [[ "$2" == nft ]]; return; fi; builtin command "$@"; }
systemctl() { return 1; }
nft() {
    case "$1 $2" in
        "list ruleset")
            cat <<'EOF'
table inet fw {
    chain input {
        type filter hook input priority 0; policy drop;
        udp dport 14617 drop
        tcp dport 18080 accept
    }
}
EOF
            ;;
        "list chain")
            cat <<'EOF'
    udp dport 14617 drop
    tcp dport 18080 accept
EOF
            ;;
        "insert rule")
            echo "INS $*" >> "$CALLS"
            ;;
    esac
    return 0
}
"""
            + _extract(self.src, 'setup_system_firewall')
            + 'setup_system_firewall 14617 "" ""\ncat "$CALLS"\n'
        )
        r = self._run(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('INS insert rule inet fw input udp dport 14617 accept', r.stdout,
                      'udp dport 14617 drop 不得被误判成已放行')
        self.assertNotIn('tcp dport 18080 accept', r.stdout, '已存在 accept 的端口应保持幂等跳过')

    def test_setup_acme_certificate_propagates_self_signed_failure_and_validates_pair_delimiter(self):
        """setup_acme_certificate 退回自签失败必须返回非零，且 Nginx/DNS 返回的证书对必须含 | 分隔符并检查非空文件。"""
        fn_src = _extract(self.src, 'setup_acme_certificate')
        self.assertIn('generate_self_signed_cert || return 1', fn_src)
        self.assertIn('"$_ngpair" == *"|"*', fn_src)
        self.assertIn('"$_dnspair" == *"|"*', fn_src)

    def test_uninstall_all_guards_hy2_dir_and_awg_dir_against_root_or_system_paths(self):
        """uninstall_all 清理 HY2_DIR 与 AWG_DIR 前必须拦截空路径、/、系统顶层目录与路径穿越，并跳过 acme 符号链接。"""
        fn_src = _extract(self.src, 'uninstall_all')
        self.assertIn('! -L "$acme_cert"', fn_src)
        self.assertIn('拒绝清理非法目录', fn_src)
        # 确保 AWG_DIR 清理前也有目录安全守卫
        awg_rm_pos = fn_src.index('rm -rf "$AWG_DIR"')
        self.assertIn('拒绝清理非法', fn_src[awg_rm_pos - 400:awg_rm_pos + 120])


if __name__ == '__main__':
    unittest.main()
