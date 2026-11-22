"""回归测试：install.sh uninstall_all 防符号链接误删目录、setup_systemd 拦截控制字符与说明符、setup_system_firewall 禁 nft 前导连字符。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = (REPO / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_fn(name):
    marker = f'{name}() {{'
    start = INSTALL_SH.index(marker)
    lines = INSTALL_SH[start:].splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        if i > 0 and line == '}':
            break
    return '\n'.join(out) + '\n'


class InstallUninstallSystemdAndNftFirewallGuardsTests(unittest.TestCase):
    def test_uninstall_all_rejects_symlink_hy2_dir_awg_dir_and_unit_files(self):
        """uninstall_all 须拒绝符号链接 HY2_DIR / AWG_DIR / drop-in / timer。"""
        fn = _extract_fn('uninstall_all')
        self.assertIn('[[ -L "$HY2_DIR" ]]', fn)
        self.assertIn('[[ ! -L "$AWG_DIR" && -n "$_awg_clean"', fn)
        self.assertIn('[[ ! -L "$HY2_LOG_DROPIN" && -f "$HY2_LOG_DROPIN" ]]', fn)
        self.assertIn('[[ ! -L /etc/systemd/system/hy2-acme-renew.timer ]]', fn)

    def test_setup_systemd_rejects_symlink_dir_ctrl_chars_and_specifiers(self):
        """setup_systemd 须拒符号链接 HY2_DIR 与 drop-in 父目录，并拦截控制字符及 %/$ 说明符。"""
        fn = _extract_fn('setup_systemd')
        self.assertIn('[[ -L "$HY2_DIR" ]]', fn)
        self.assertIn('[[:cntrl:]]', fn)
        self.assertIn('[%$]', fn)
        self.assertIn('[[ -L "${HY2_LOG_DROPIN%/*}" || -L "$HY2_LOG_DROPIN" ]]', fn)

        bash = _find_bash()
        script = (
            'set -euo pipefail\n'
            'log_step() { :; }; log_err() { printf "ERR:%s\\n" "$*" >&2; }; log_warn() { :; }; log_info() { :; }\n'
            'HY2_DIR="/tmp/hy2-%i-test"\n'
            'HY2_BIN="/usr/local/bin/hysteria"\n'
            'HY2_CONFIG="/etc/hysteria/config.yaml"\n'
            'HY2_SERVICE="/etc/systemd/system/hysteria-server.service"\n'
            'HY2_LOG_DROPIN="/etc/systemd/system/hysteria-server.service.d/10-log-level.conf"\n'
            'mkdir() { echo "UNEXPECTED_MKDIR" >&2; exit 99; }\n'
            + fn
            + 'if setup_systemd; then echo "ALLOWED_SPECIFIER"; exit 11; fi\n'
            + 'echo REJECTED_SPECIFIER\n'
        )
        res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('REJECTED_SPECIFIER', res.stdout)
        self.assertNotIn('UNEXPECTED_MKDIR', res.stderr)

    def test_setup_system_firewall_rejects_leading_dash_nft_identifiers(self):
        """setup_system_firewall 解析出的 nft family/table/chain 不得允许前导连字符。"""
        fn = _extract_fn('setup_system_firewall')
        self.assertIn('^[A-Za-z0-9_.][A-Za-z0-9_.-]*$', fn)
        self.assertNotIn('^[A-Za-z0-9_.-]+$', fn)


if __name__ == '__main__':
    unittest.main()
