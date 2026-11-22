"""回归测试：install.sh 核心锁防符号链接与追加打开、Caddy 借证防符号链接与限体积、acme 续期定时器防符号链接与特殊字符、自签证书防符号链接与精确 CN 匹配。"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _extract_fn(name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


class TestInstallCoreLockCaddyRenewTimerAndSelfsignedSymlinkGuards(unittest.TestCase):
    def test_acquire_installer_core_lock_rejects_symlinks_and_opens_append_umask_077(self):
        """acquire_installer_core_lock 必须拒绝符号链接目录/锁文件，并以 umask 077 追加模式 >> 打开锁文件。"""
        body = _extract_fn('acquire_installer_core_lock')
        self.assertIn('-L "$HY2_DIR"', body, '必须拒绝符号链接形式的 $HY2_DIR')
        self.assertIn('-L "$_lock_file"', body, '必须拒绝符号链接形式的核心锁文件')
        self.assertIn('exec {lock_fd}>>"$_lock_file"', body, '锁文件必须以追加模式 >> 打开防截断')
        self.assertIn('umask 077', body, '锁文件必须在 umask 077 下创建')

    def test_setup_cert_via_existing_caddy_guards_symlinks_and_bounds_probe_curl(self):
        """setup_cert_via_existing_caddy 必须拒绝符号链接 Caddyfile、私有权限备份并给探测 curl 设 --max-filesize。"""
        start = INSTALL_SH.index('setup_cert_via_existing_caddy() {')
        end = INSTALL_SH.index('hy2_acme_ensure() {', start)
        body = INSTALL_SH[start:end]
        self.assertIn('-L "$cf"', body, '必须拒绝符号链接形式的 /etc/caddy/Caddyfile')
        self.assertIn('umask 077 && cp -a -- "$cf" "$bak"', body, '备份 Caddyfile 须在 umask 077 下执行并加 --')
        self.assertIn('--max-filesize 65536', body, '触发签发探测 curl 必须加 --max-filesize 上限')

    def test_hy2_acme_ensure_renew_timer_guards_unit_symlinks_and_specifiers(self):
        """hy2_acme_ensure_renew_timer 必须拒绝含 %/$ 的路径、拒绝符号链接目标单元并校验 chmod 结果。"""
        body = _extract_fn('hy2_acme_ensure_renew_timer')
        self.assertIn(r'%\$', body, '必须拒绝含 % 或 $ 的 $home 防止 systemd specifier/变量注入')
        self.assertIn('-L "${unit_dir}/hy2-acme-renew.service"', body, '写入 service 单元前必须拒绝符号链接')
        self.assertIn('-L "${unit_dir}/hy2-acme-renew.timer"', body, '写入 timer 单元前必须拒绝符号链接')
        self.assertNotIn('chmod 0644 "$svc_tmp" 2>/dev/null || true', body, 'chmod 失败不得吞错')

    def test_generate_self_signed_cert_guards_symlinks_return_trap_and_exact_cn(self):
        """generate_self_signed_cert 必须拒绝目录/文件符号链接、挂 RETURN 清理陷阱并精确转义 CN 点号。"""
        body = _extract_fn('generate_self_signed_cert')
        self.assertIn('-L "$HY2_CERT_DIR"', body, '必须拒绝符号链接证书目录')
        self.assertIn('-L "$CERT_FILE"', body, '必须拒绝符号链接证书文件')
        self.assertIn('-L "$KEY_FILE"', body, '必须拒绝符号链接私钥文件')
        self.assertRegex(body, r"trap\s+'.*'\s+RETURN", '必须注册 RETURN 清理陷阱防止残留临时私钥')
        self.assertNotIn('grep -q "CN *= *${SERVER_NAME}"', body, 'CN 匹配不得把点号当任意通配符')


if __name__ == '__main__':
    unittest.main()
