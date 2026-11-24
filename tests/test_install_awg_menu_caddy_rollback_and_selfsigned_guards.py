"""回归测试：install.sh AWG 菜单名称/地址参数对齐、符号链接拒绝、Caddyfile 回滚防线与自签落盘 -- 防护。"""

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


class InstallAwgMenuCaddyRollbackAndSelfsignedGuardsTests(unittest.TestCase):
    def test_awg_helpers_and_menus_align_name_endpoint_and_symlink_guards(self):
        """install_amneziawg / awg_menu_add_peer / awg_menu_del_peer 须与 awgctl 对齐名称/地址校验并拒符号链接。"""
        fn_sug = _extract_fn('awg_suggest_endpoint')
        self.assertIn('[[ ! -L "$HY2_META_FILE" && -f "$HY2_META_FILE" ]]', fn_sug)

        fn_line = _extract_fn('awg_current_line')
        self.assertIn('[[ ! -L "$AWG_META_FILE" && -f "$AWG_META_FILE" ]]', fn_line)

        fn_inst = _extract_fn('install_amneziawg', '\nawg_menu_add_peer() {')
        self.assertIn('"$client" == -* || "$client" == .* || "$client" == _*', fn_inst)
        self.assertIn('[[ "$endpoint" == -* || "$endpoint" =~ [[:space:][:cntrl:]] ]]', fn_inst)
        self.assertIn('[[ ! -L "$AWG_PEERS_FILE" && -f "$AWG_PEERS_FILE" ]]', fn_inst)

        fn_add = _extract_fn('awg_menu_add_peer')
        self.assertIn('[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ ]]', fn_add)
        self.assertIn('[[ "$endpoint" == -* || "$endpoint" =~ [[:space:][:cntrl:]] ]]', fn_add)

        fn_del = _extract_fn('awg_menu_del_peer')
        self.assertIn('[[ "$name" == -* || "$name" =~ [[:cntrl:]] ]]', fn_del)

    def test_caddy_rollback_and_self_signed_mv_guards(self):
        """setup_cert_via_existing_caddy 回滚须拒符号链接并补 --；generate_self_signed_cert 须为 chmod/mv 补 --。"""
        fn_caddy = _extract_fn('setup_cert_via_existing_caddy', '\n# 确保 acme.sh 可用')
        self.assertIn('[[ ! -L "$cf" && ! -L "$bak" ]]', fn_caddy)
        self.assertIn('cp -p -- "$bak" "$rb_tmp"', fn_caddy)
        self.assertIn('mv -f -- "$rb_tmp" "$cf"', fn_caddy)

        fn_ss = _extract_fn('generate_self_signed_cert')
        self.assertIn('chmod 600 -- "$tmp_key"', fn_ss)
        self.assertIn('mv -f -- "$tmp_key" "$KEY_FILE"', fn_ss)

    def test_runtime_awg_menu_rejects_leading_dash_peer_name(self):
        """真实 bash 行为测试：awg_menu_add_peer 与 awg_menu_del_peer 必须拒绝以 - 开头的客户端名称。"""
        bash = _find_bash()
        fn_add = _extract_fn('awg_menu_add_peer')
        fn_del = _extract_fn('awg_menu_del_peer')
        script = (
            'set -euo pipefail\n'
            'check_root() { :; }\n'
            'awg_ensure_ctl() { return 0; }\n'
            'awg_suggest_endpoint() { echo "1.2.3.4"; }\n'
            'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            'AWG_CTL_BIN="true"\n'
            + fn_add + '\n' + fn_del + '\n'
            + 'if printf -- "-badname\\n" | awg_menu_add_peer; then exit 11; fi\n'
            + 'if printf -- "-badname\\n" | awg_menu_del_peer; then exit 12; fi\n'
            + 'echo DASH_NAMES_REJECTED\n'
        )
        res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('DASH_NAMES_REJECTED', res.stdout)


if __name__ == '__main__':
    unittest.main()
