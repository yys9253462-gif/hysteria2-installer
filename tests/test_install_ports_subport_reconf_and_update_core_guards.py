"""回归测试：install.sh setup_ports_and_obfs / select_subscription_port / flow_update_core / close_replaced_ports 符号链接、-I 隔离、密码与 obfs 清洗守卫。"""

import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = (REPO / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用 bash')


def _extract_fn(name, next_marker=None):
    marker = f'{name}() {{'
    start = INSTALL_SH.index(marker)
    if next_marker:
        end = INSTALL_SH.index(next_marker, start)
        return INSTALL_SH[start:end]
    lines = INSTALL_SH[start:].splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        if i > 0 and line == '}':
            break
    return '\n'.join(out) + '\n'


class InstallPortsSubportReconfAndUpdateCoreGuardsTests(unittest.TestCase):
    def test_setup_ports_and_obfs_validates_password_bounds_obfs_ctrl_and_symlinks(self):
        """setup_ports_and_obfs 须校验密码长度/首尾空白、API Key 长度、obfs 控制字符并拒绝符号链接 meta/portal.json。"""
        fn = _extract_fn('setup_ports_and_obfs', '\nsetup_system_firewall() {')
        self.assertIn('(( ${#AUTH_PASSWORD} > 256 ))', fn)
        self.assertIn('(( ${#NODE_API_KEY} > 256 ))', fn)
        self.assertIn('[[ "$_old_obfs" =~ [[:cntrl:]] ]]', fn)
        self.assertIn('[[ ! -L "$HY2_META_FILE" && -f "$HY2_META_FILE" ]]', fn)
        self.assertIn('[[ ! -L "$HY2_DIR/portal.json" && -f "$HY2_DIR/portal.json" ]]', fn)

    def test_select_subscription_port_uses_python_isolated_and_guards_portal_symlink(self):
        """select_subscription_port 须以 lstat/S_ISREG 校验 portal.json，沿用分支须拒符号链接且本地端口用 python3 -I。"""
        fn = _extract_fn('select_subscription_port', '\n# 删掉带本安装器所有权标记')
        self.assertIn('python3 -I - ', fn)
        self.assertIn('[[ ! -L "$HY2_META_FILE" && -f "$HY2_META_FILE" ]]', fn)
        self.assertIn('[[ ! -L "$HY2_DIR/portal.json" && -f "$HY2_DIR/portal.json" ]]', fn)
        self.assertGreaterEqual(fn.count('stat.S_ISREG('), 2)

    def test_flow_update_core_and_close_ports_guard_symlinks_and_dashes(self):
        """flow_update_core 备份/清理须补 -- 并在回滚前复检符号链接；close_replaced_ports / close_installer_ports 须拒符号链接。"""
        fn_upd = _extract_fn('flow_update_core', '\nflow_reconfigure() {')
        self.assertIn('cp -p -- "$HY2_BIN" "$rollback_file"', fn_upd)
        self.assertIn('[[ -L "$HY2_BIN" ]] || ! mv -f "$rollback_file" "$HY2_BIN"', fn_upd)
        self.assertIn('rm -f -- "$rollback_file"', fn_upd)

        fn_cr = _extract_fn('close_replaced_ports', '\n# 卸载时收回本工具放行过')
        self.assertIn('[[ ! -L "$HY2_DIR/portal.json" && -f "$HY2_DIR/portal.json" ]]', fn_cr)

        fn_ci = _extract_fn('close_installer_ports', '\nflow_refresh_portal() {')
        self.assertIn('[[ ! -L "$HY2_META_FILE" && -f "$HY2_META_FILE" ]]', fn_ci)

    def test_runtime_setup_ports_rejects_overlong_password(self):
        """真实 bash 行为测试：setup_ports_and_obfs 必须拒绝超过 256 字符的 HY2_PASSWORD。"""
        bash = _find_bash()
        fn = _extract_fn('setup_ports_and_obfs', '\nsetup_system_firewall() {')
        fn_vp = _extract_fn('is_valid_port')
        script = (
            'set -euo pipefail\n'
            'CYAN="" GREEN="" YELLOW="" PLAIN=""\n'
            'log_info() { :; }; log_warn() { :; }; log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'HY2_DIR="/tmp/hy2-nonexistent-dir"\n'
            'HY2_META_FILE="/tmp/hy2-nonexistent-meta.json"\n'
            'HY2_PORT=18888\n'
            'HY2_PASSWORD="$(printf \'a%.0s\' {1..260})"\n'
            + fn_vp + '\n' + fn
            + 'if setup_ports_and_obfs; then exit 11; fi\n'
            + 'echo OVERLONG_PASS_REJECTED\n'
        )
        res = subprocess.run([bash, '-c', script], input='\n\n\n', capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('OVERLONG_PASS_REJECTED', res.stdout)
        self.assertIn('256', res.stderr)


if __name__ == '__main__':
    unittest.main()
