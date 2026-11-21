"""回归测试：WARP 安装脚本、toggle_warp 与 watchdog 的安全落盘、归档校验与 reset-failed 防护。"""
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL_TEXT = (ROOT / 'portal.py').read_text(encoding='utf-8')
INSTALL_TEXT = (ROOT / 'install.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash') or 'bash'


def _extract_portal_warp_script():
    m = re.search(r"install_warp_sh = r'''(.*?)'''", PORTAL_TEXT, re.S)
    assert m, '未在 portal.py 中找到 WARP 安装内嵌脚本'
    return m.group(1)


def _extract_toggle_warp_script():
    m = re.search(r"cat > \"\$HY2_DIR/toggle_warp\.sh\" <<'EOTW'\n(.*?)\nEOTW", INSTALL_TEXT, re.S)
    assert m, '未在 install.sh 中找到 toggle_warp.sh 模板'
    return m.group(1)


class WarpScriptHardeningTests(unittest.TestCase):
    def test_portal_warp_tar_member_rejects_corrupt_truncated_archive(self):
        script = _extract_portal_warp_script()
        m = re.search(r'(tar_member\(\) \{.*?\n\})', script, re.S)
        self.assertIsNotNone(m, '未找到 tar_member 函数定义')
        fn_body = m.group(1)
        with tempfile.TemporaryDirectory() as td:
            bad_tgz = Path(td) / 'truncated.tar.gz'
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w:gz') as tf:
                first = tarfile.TarInfo('wireproxy')
                first.size = 4
                tf.addfile(first, io.BytesIO(b'bin!'))
                second = tarfile.TarInfo('padding.bin')
                payload = os.urandom(65536)
                second.size = len(payload)
                tf.addfile(second, io.BytesIO(payload))
            # 截断后半段 gzip 流：tar 会先输出 wireproxy 再因 EOF 报非零退出码
            raw = buf.getvalue()
            bad_tgz.write_bytes(raw[: len(raw) // 2])
            cmd = f'{fn_body}\ntar_member wireproxy "truncated.tar.gz"\n'
            res = subprocess.run([BASH, '-c', cmd], cwd=td, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(res.returncode, 0, f'损坏截断的压缩包被 tar_member 放行: stdout={res.stdout!r}')

            # 合法归档仍应正常识别并返回成员名
            good_tgz = Path(td) / 'good.tar.gz'
            good_tgz.write_bytes(raw)
            res_ok = subprocess.run([BASH, '-c', f'{fn_body}\ntar_member wireproxy "good.tar.gz"\n'],
                                    cwd=td, capture_output=True, text=True, timeout=15)
            self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
            self.assertEqual(res_ok.stdout.strip(), 'wireproxy')

    def test_toggle_warp_script_execution_preserves_obfs_and_leaves_no_temp_files(self):
        script = _extract_toggle_warp_script()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cfg = td_path / 'config.yaml'
            cfg.write_text('listen: :443\nacl:\n  inline:\n    - direct_ipv4(all)\nobfs:\n  type: salamander\n', encoding='utf-8')
            toggle = td_path / 'toggle_warp.sh'
            toggle.write_bytes(script.replace('/etc/hysteria/config.yaml', str(cfg)).encode('utf-8'))
            fake_bin = td_path / 'bin'
            fake_bin.mkdir()
            for tool in ('curl', 'systemctl', 'jq'):
                p = fake_bin / tool
                p.write_bytes(b'#!/usr/bin/env bash\nexit 0\n')
                os.chmod(p, 0o755)
            env = dict(os.environ)
            env['PATH'] = str(fake_bin) + os.pathsep + env.get('PATH', '')
            res = subprocess.run([BASH, str(toggle), '1'], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr)
            text = cfg.read_text(encoding='utf-8')
            self.assertIn('obfs:\n  type: salamander', text)
            self.assertIn('warp_socks(suffix:openai.com)', text)
            leftovers = [f.name for f in td_path.iterdir() if f.name.startswith('config.yaml.')]
            self.assertEqual(leftovers, [], f'残留临时文件: {leftovers}')

    def test_wp_conf_written_atomically_under_umask_077(self):
        portal_script = _extract_portal_warp_script()
        self.assertNotIn('cat > "$WP_CFG" <<WPEOF', portal_script, 'portal.py 仍在默认 umask 下直接覆写 wp.conf')
        self.assertIn('umask 077', portal_script)
        self.assertNotIn('cat > "$WP_CFG" <<EOF', INSTALL_TEXT, 'install.sh 仍在默认 umask 下直接覆写 wp.conf')

    def test_toggle_warp_rewrites_config_atomically_with_umask_077_and_resets_failed_wireproxy(self):
        script = _extract_toggle_warp_script()
        self.assertNotIn('> "$CONFIG.tmp"', script, 'toggle_warp.sh 仍在使用固定临时名 $CONFIG.tmp')
        self.assertIn('umask 077', script)
        self.assertIn('mktemp', script)
        self.assertIn('systemctl reset-failed wireproxy', script)

    def test_warp_restarts_and_watchdogs_reset_failed_before_restart(self):
        portal_script = _extract_portal_warp_script()
        self.assertGreaterEqual(portal_script.count('systemctl reset-failed wireproxy'), 2)
        m = re.search(r'cat > /usr/local/bin/hy2-warp-watchdog\.sh <<EOWD\n(.*?)\nEOWD', INSTALL_TEXT, re.S)
        self.assertIsNotNone(m)
        self.assertIn('systemctl reset-failed wireproxy', m.group(1))


if __name__ == '__main__':
    unittest.main()
