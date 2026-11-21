import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL = (REPO / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _extract_fn(name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}')
    return m.group(0)


class TestInstallAcmeAtomicAndPortCleanupGuards(unittest.TestCase):
    def test_acme_disable_auto_upgrade_atomic_replace_and_curl_bounds(self):
        """hy2_acme_disable_auto_upgrade 必须原子替换而非 cat 截断覆写，且 ACME curl 应限制体积。"""
        fn = _extract_fn('hy2_acme_disable_auto_upgrade')
        self.assertIn('umask 077', fn)
        self.assertIn('mv -f "$tmp" "$conf"', fn)
        self.assertNotIn('cat "$tmp" > "$conf"', fn)

        for name in ('hy2_acme_pin_commit', 'hy2_acme_tree_json', 'hy2_acme_fetch_verified'):
            self.assertIn('--max-filesize', _extract_fn(name), f'{name} 缺少 --max-filesize 体积上限')

        for name in ('hy2_acme_install_verified', 'hy2_acme_verify_existing'):
            body = _extract_fn(name)
            self.assertIn('umask 077', body, f'{name} 临时目录未设置 umask 077')
            self.assertIn('RETURN', body, f'{name} 缺少 RETURN 临时目录清理陷阱')

    def test_acme_same_except_shebang_rejects_symlink_destination(self):
        """hy2_acme_same_except_shebang 必须拒绝符号链接目标文件。"""
        fn = _extract_fn('hy2_acme_same_except_shebang')
        self.assertIn('! -L "$dst"', fn)

    def test_port_cleanup_handles_string_ports_dedup_and_inverted_hop_range(self):
        """close_replaced_ports 与 close_installer_ports 须兼容字符串端口、去重并拒绝倒置跳跃区间。"""
        crp = _extract_fn('close_replaced_ports')
        cip = _extract_fn('close_installer_ports')
        self.assertIn('type=="string"', crp)
        self.assertIn('type=="string"', cip)
        self.assertIn('10#$lo <= 10#$hi', cip)
        self.assertIn('sort -u', cip)

    @unittest.skipUnless(_find_bash(), '需要 bash 执行真实函数验证')
    def test_acme_disable_auto_upgrade_runtime_preserves_secrets_and_updates_atomically(self):
        """真实运行 hy2_acme_disable_auto_upgrade，验证保留 DNS 密钥、不留临时文件且正确关闭自动升级。"""
        bash = _find_bash()
        fn = _extract_fn('hy2_acme_disable_auto_upgrade')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            conf = td_path / 'account.conf'
            conf.write_text("SAVED_CF_Token='secret-token-123'\nAUTO_UPGRADE='1'\n", encoding='utf-8')
            script = f"""
set -euo pipefail
{fn}
hy2_acme_disable_auto_upgrade "{conf.as_posix()}"
"""
            res = subprocess.run([bash, '-c', script], capture_output=True, text=True, encoding='utf-8', timeout=10)
            self.assertEqual(res.returncode, 0, f'bash 失败:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}')
            text = conf.read_text(encoding='utf-8')
            self.assertIn("SAVED_CF_Token='secret-token-123'", text)
            self.assertIn("AUTO_UPGRADE='0'", text)
            leftovers = [p.name for p in td_path.iterdir() if p.name.startswith('.account.conf.')]
            self.assertEqual(leftovers, [])


if __name__ == '__main__':
    unittest.main()
