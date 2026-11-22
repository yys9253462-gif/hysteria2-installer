"""回归测试：install.sh 中 setup_systemd、portal_ensure_py、portal_write_meter_config 与 install_gost 的符号链接/锁 O_NOFOLLOW、METER_SECRET 防 YAML 注入、临时文件清理陷阱及 GOST 证书半缺失修复。"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


def _extract_func(name: str) -> str:
    start = INSTALL_SH.index(f'{name}() {{')
    # 找到下一个顶层函数或闭合大括号
    m = re.search(rf'^{re.escape(name)}\(\) \{{.*?\n\}}', INSTALL_SH[start:], re.M | re.S)
    assert m, f'未找到函数 {name}'
    return m.group(0)


class TestInstallSystemdPortalBundleMeterAndGostCertGuards(unittest.TestCase):
    def test_setup_systemd_guards_symlinks_and_unit_newlines(self):
        """setup_systemd 须拒 .hy2-installer-owned/服务单元符号链接、以 umask 077 建临时文件并拦路径换行注入。"""
        body = _extract_func('setup_systemd')
        self.assertIn('[[ -L "$HY2_SERVICE" ]]', body)
        self.assertIn('[[ -L "$HY2_DIR/.hy2-installer-owned" ]]', body)
        self.assertIn('umask 077', body)
        self.assertIn('*$\'\\n\'*', body, 'setup_systemd 写入单元前必须拦截路径变量中的换行控制字符')

    def test_portal_ensure_py_uses_o_nofollow_lock_and_rejects_symlink_backup_root(self):
        """portal_ensure_py 的 PYINSTALLBUNDLE 锁必须用 O_NOFOLLOW 打开，并拒绝符号链接 backups 目录。"""
        body = _extract_func('portal_ensure_py')
        self.assertIn("getattr(os, 'O_NOFOLLOW', 0)", body,
                      '打开 .portal-update.lock 必须叠加 O_NOFOLLOW 防符号链接跟随')
        self.assertIn('backup_root.is_symlink()', body,
                      'backups 目录不允许为符号链接')

    def test_portal_write_meter_config_blocks_yaml_injection_and_guards_chmod_failure(self):
        """portal_write_meter_config 必须拦截含换行/控制字符/引号的 METER_SECRET，限制 config.yaml 读盘上限并检查 chmod 失败。"""
        body = _extract_func('portal_write_meter_config')
        self.assertIn('4 * 1024 * 1024', body, '读取 config.yaml 必须施加 4 MiB 上限')
        self.assertIn('[[ ! "$_meter_secret_cand" =~', body)
        self.assertIn('if ! chmod 600 "$_meter_tmp" || ! mv -f "$_meter_tmp" "${dest_dir}/usage-meter-config.json"; then', body)

        # 动态验证内联 PYEOF 拒绝含换行的 METER_SECRET（防 YAML 顶层注入）
        m = re.search(r"python3 -I - \"\$HY2_CONFIG\" \"\$METER_SECRET\" <<'PYEOF'\n(.*?)\nPYEOF\n", body, re.S)
        self.assertIsNotNone(m, '未找到 portal_write_meter_config 内联 PYEOF')
        py_code = m.group(1)
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\nmasquerade:\n  type: proxy\n', encoding='utf-8')
            r = subprocess.run(
                ['python3' if shutil.which('python3') else 'python', '-I', '-c', py_code,
                 str(cfg), 'abc\ninjected: true'],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(r.returncode, 0, 'PYEOF 不得接受含换行的 secret 写入 config.yaml')
            self.assertNotIn('injected:', cfg.read_text(encoding='utf-8'))

    def test_install_gost_guards_cert_symlinks_and_partial_cert_key_pair(self):
        """install_gost 必须在 cert.pem 或 key.pem 任一缺失时重签、拒符号链接并检查 TMP_DIR 创建失败。"""
        body = _extract_func('install_gost')
        self.assertIn('TMP_DIR=$(umask 077; mktemp -d) || {', body)
        self.assertIn('[[ -L "$GOST_CERT_DIR/cert.pem" || -L "$GOST_CERT_DIR/key.pem" ]]', body)
        self.assertIn('[[ ! -f "$GOST_CERT_DIR/cert.pem" || ! -f "$GOST_CERT_DIR/key.pem" ]]', body,
                      '仅 cert.pem 存在而 key.pem 缺失时必须补生成配对证书')
        self.assertIn('chmod 700 "$GOST_CERT_DIR"', body)


if __name__ == '__main__':
    unittest.main()
