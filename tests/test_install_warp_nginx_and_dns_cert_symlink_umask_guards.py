"""回归测试：install.sh install_warp_local_proxy / setup_cert_via_nginx / setup_cert_via_dns_api 符号链接、umask 077、私钥收紧与探活限流守卫。"""

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


class InstallWarpNginxAndDnsCertSymlinkUmaskGuardsTests(unittest.TestCase):
    def test_install_warp_local_proxy_guards_symlinks_member_umask_and_probe_filesize(self):
        """install_warp_local_proxy 须前置拒符号链接、验解压成员非符号链接、收紧 systemd 暂存 umask 077 且探活限体积。"""
        fn = _extract_fn('install_warp_local_proxy')
        self.assertIn('for _wpath in "$WGCF_BIN" "$WP_BIN" "$HY2_WARP_OWNED_MARKER" "$WGCF_DIR" "$WGCF_ACCT" "$WGCF_CONF" /etc/wireguard/wp.conf /etc/systemd/system/wireproxy.service /usr/local/bin/hy2-warp-watchdog.sh /etc/systemd/system/hy2-warp-watchdog.service /etc/systemd/system/hy2-warp-watchdog.timer; do', fn)
        self.assertIn('[[ -L "$_wpath" ]]', fn)
        self.assertIn('[[ ! -f "${TMP_EXTRACT}/${WP_MEMBER}" || -L "${TMP_EXTRACT}/${WP_MEMBER}" ]]', fn)
        self.assertIn('_wp_unit_tmp="$(umask 077; mktemp "/etc/systemd/system/wireproxy.service.XXXXXX")"', fn)
        self.assertIn('_wd_svc_tmp="$(umask 077; mktemp "/etc/systemd/system/hy2-warp-watchdog.service.XXXXXX")"', fn)
        self.assertIn('_wd_tmr_tmp="$(umask 077; mktemp "/etc/systemd/system/hy2-warp-watchdog.timer.XXXXXX")"', fn)
        self.assertIn('--max-filesize 65536 https://api4.ipify.org', fn)

    def test_setup_cert_via_nginx_and_dns_api_guard_symlinks_and_key_chmod(self):
        """setup_cert_via_nginx 与 setup_cert_via_dns_api 须拒绝悬空/普通符号链接目标，且 Nginx 私钥 chmod 600 失败须中止。"""
        fn_ng = _extract_fn('setup_cert_via_nginx', '\n# 🔴 兜底路线：')
        self.assertIn('[[ -e "$conf" || -L "$conf" ]]', fn_ng)
        self.assertIn('[[ -L "$HY2_CERT_DIR" || -L "$out_cert" || -L "$out_key" ]]', fn_ng)
        self.assertIn('chmod 600 "$out_key" || {', fn_ng)

        fn_dns = _extract_fn('setup_cert_via_dns_api')
        self.assertIn('[[ -L "$HY2_CERT_DIR" || -L "$out_cert" || -L "$out_key" ]]', fn_dns)

        # 真 bash 行为校验：setup_cert_via_dns_api 在 HY2_CERT_DIR 无效（此处测非法域名早退）仍保持原行为
        bash = _find_bash()
        script = (
            'set -euo pipefail\n'
            'log_err() { printf "ERR:%s\\n" "$*" >&2; }\n'
            + fn_dns
            + 'if ( setup_cert_via_dns_api "bad;domain" ); then exit 11; fi\n'
            + 'echo DNS_BAD_REJECTED\n'
        )
        res = subprocess.run([bash, '-c', script], capture_output=True, text=True, errors='replace', timeout=15)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('DNS_BAD_REJECTED', res.stdout)


if __name__ == '__main__':
    unittest.main()
