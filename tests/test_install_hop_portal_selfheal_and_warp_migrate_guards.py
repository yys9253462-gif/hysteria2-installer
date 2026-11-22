"""回归测试：install.sh 端口跳跃单元、门户单元、证书自愈与 WARP 迁移的符号链接与注入防护。"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = (REPO / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (
        r'C:\Program Files\Git\bin\bash.exe',
        shutil.which('bash'),
    ):
        if cand and Path(cand).is_file():
            return cand
    raise RuntimeError('未找到可用的 bash 解释器')


def _extract_sh_func(src, name):
    marker = f'{name}() {{'
    start = src.index(marker)
    lines = src[start:].splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        if i > 0 and line == '}':
            break
    return '\n'.join(out) + '\n'


class InstallHopPortalSelfhealAndWarpMigrateGuardsTests(unittest.TestCase):
    def test_iptables_unit_owned_and_hop_setup_reject_symlinks(self):
        """_hy2_iptables_unit_owned 与端口跳跃清理/写入须拒绝符号链接并收紧临时文件 umask。"""
        fn_owned = _extract_sh_func(INSTALL_SH, '_hy2_iptables_unit_owned')
        fn_clear = _extract_sh_func(INSTALL_SH, 'clear_all_hopping_rules')
        fn_setup = _extract_sh_func(INSTALL_SH, 'setup_iptables_port_hopping')

        self.assertIn('[[ ! -L "$unit" && -f "$unit" ]]', fn_owned)
        self.assertIn('[[ ! -L "$HY2_META_FILE" && -f "$HY2_META_FILE" ]]', fn_clear)
        self.assertIn('rm -f -- /etc/systemd/system/hy2-iptables.service', fn_clear)
        self.assertIn('[[ -L "$_ipt_unit" ]]', fn_setup)
        self.assertIn('umask 077; mktemp "${_ipt_unit}.XXXXXX"', fn_setup)
        self.assertIn('mv -f -- "$_ipt_unit_tmp" "$_ipt_unit"', fn_setup)

    def test_setup_portal_guards_hy2_dir_specifiers_and_unit_symlink(self):
        """setup_portal 写 systemd 单元前须拒绝符号链接及含 %/$/控制字符的 HY2_DIR。"""
        fn_portal = _extract_sh_func(INSTALL_SH, 'setup_portal')
        self.assertIn('[[ -L /etc/systemd/system/hysteria-portal.service ]]', fn_portal)
        self.assertIn('[[ -L "$HY2_DIR" || "$HY2_DIR" =~ [[:cntrl:]%\\$] ]]', fn_portal)
        self.assertIn('mv -f -- "$_portal_svc_tmp" /etc/systemd/system/hysteria-portal.service', fn_portal)

    def test_setup_cert_selfheal_guards_symlinks_umask_specifiers_and_reload(self):
        """setup_cert_selfheal 须拒绝 4 个目标为符号链接、统一 umask 077、防 % 注入并检查 daemon-reload。"""
        fn_sh = _extract_sh_func(INSTALL_SH, 'setup_cert_selfheal')
        for target in (
            '/usr/local/bin/hy2-cert-selfheal.sh',
            '/etc/systemd/system/hy2-cert-selfheal.service',
            '/etc/systemd/system/hy2-cert-selfheal.timer',
            '/etc/systemd/system/hy2-cert-selfheal.path',
        ):
            self.assertIn(target, fn_sh)
        self.assertIn('[[ -L "$_sh_target" ]]', fn_sh)
        self.assertIn('umask 077; mktemp /etc/systemd/system/hy2-cert-selfheal.timer.XXXXXX', fn_sh)
        self.assertIn('umask 077; mktemp /etc/systemd/system/hy2-cert-selfheal.path.XXXXXX', fn_sh)
        self.assertIn('[[ -d "$cert_watch_dir" && ! -L "$cert_watch_dir" && ! "$cert_watch_dir" =~ [[:cntrl:]%\\$] ]]', fn_sh)
        self.assertIn('systemctl daemon-reload || return 1', fn_sh)

    def test_warp_migrate_legacy_outbound_runtime_validation_and_trap(self):
        """warp_migrate_legacy_outbound 须拒绝空/脏地址与符号链接配置，并挂 RETURN 清理陷阱。"""
        fn_warp = _extract_sh_func(INSTALL_SH, 'warp_migrate_legacy_outbound')
        self.assertIn('trap \'trap - RETURN; rm -f -- "${_wm_tmp:-}"\' RETURN', fn_warp)
        self.assertIn('[[ -L "$HY2_CONFIG" ]]', fn_warp)

        bash = _find_bash()
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            original = 'outbounds:\n  - name: warp\n    socks5:\n      addr: 127.0.0.1:40000\n'
            cfg.write_text(original, encoding='utf-8')
            cfg_posix = cfg.as_posix()
            if len(cfg_posix) >= 2 and cfg_posix[1] == ':':
                cfg_posix = '/' + cfg_posix[0].lower() + cfg_posix[2:]

            script = (
                'set -euo pipefail\n'
                'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
                'systemctl() { return 0; }\n'
                f'HY2_CONFIG="{cfg_posix}"\n'
                + fn_warp
                + 'if warp_migrate_legacy_outbound ""; then echo "EMPTY_ALLOWED"; exit 11; fi\n'
                + 'if warp_migrate_legacy_outbound "127.0.0.1:19898 bad"; then echo "SPACE_ALLOWED"; exit 12; fi\n'
                + 'if warp_migrate_legacy_outbound $\'127.0.0.1:19898\\ninjected: true\'; then echo "NL_ALLOWED"; exit 13; fi\n'
                + 'warp_migrate_legacy_outbound "127.0.0.1:19898"\n'
            )
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, f'bash 执行失败: stdout={res.stdout!r} stderr={res.stderr!r}')
            after = cfg.read_text(encoding='utf-8')
            self.assertIn('addr: 127.0.0.1:19898', after)
            self.assertNotIn('127.0.0.1:40000', after)


if __name__ == '__main__':
    unittest.main()
