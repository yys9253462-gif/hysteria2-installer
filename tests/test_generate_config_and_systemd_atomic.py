"""回归测试：install.sh 的 generate_server_config 与 setup_systemd 必须通过同目录临时文件原子写入配置、元数据与服务单元。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')


def _extract_fn(source: str, name: str, end_marker: str) -> str:
    start = source.index(f'{name}() {{\n')
    end = source.index(end_marker, start)
    return source[start:end]


@unittest.skipUnless(BASH, '需要 bash 环境')
class GenerateConfigAndSystemdAtomicTests(unittest.TestCase):
    def test_generate_server_config_writes_config_and_meta_atomically(self):
        """generate_server_config 不得裸截断覆盖 $HY2_CONFIG 或 $HY2_META_FILE，obfs 须在原子替换前拼齐。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'generate_server_config', '\nsetup_systemd() {\n')
        self.assertNotIn('cat > "$HY2_CONFIG"', fn, '仍直接裸截断覆写 $HY2_CONFIG')
        self.assertNotIn('cat >> "$HY2_CONFIG"', fn, '仍直接分片追加 $HY2_CONFIG，中途中断会留半截配置')
        self.assertNotIn('\'$ARGS.named\' > "$HY2_META_FILE"', fn, '仍直接裸覆写含密码的 $HY2_META_FILE')
        self.assertIn('mv -f "$_cfg_tmp" "$HY2_CONFIG"', fn)
        self.assertIn('mv -f "$_meta_tmp" "$HY2_META_FILE"', fn)

    def test_setup_systemd_writes_sysctl_unit_and_dropin_atomically(self):
        """setup_systemd 写入 sysctl、service 与日志 drop-in 均应经同目录临时文件原子替换。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'setup_systemd', '\n# 6. 显示私密信息页')
        self.assertNotIn('cat > /etc/sysctl.d/99-hysteria2.conf', fn)
        self.assertNotIn('cat > "$HY2_SERVICE"', fn)
        self.assertNotIn('cat > "$HY2_LOG_DROPIN"', fn)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hy2_dir = root / 'etc/hysteria'
            sysd = root / 'etc/systemd/system'
            sysctl_dir = root / 'etc/sysctl.d'
            for d in (hy2_dir, sysd, sysctl_dir):
                d.mkdir(parents=True, exist_ok=True)
            patched = fn.replace('/etc/sysctl.d/99-hysteria2.conf', (sysctl_dir / '99-hysteria2.conf').as_posix())
            script = Path(td) / 'run_systemd.sh'
            script.write_text('\n'.join([
                'set -euo pipefail',
                f'HY2_DIR="{hy2_dir.as_posix()}"',
                f'HY2_BIN="/usr/local/bin/hysteria"',
                f'HY2_CONFIG="{(hy2_dir / "config.yaml").as_posix()}"',
                f'HY2_SERVICE="{(sysd / "hysteria-server.service").as_posix()}"',
                f'HY2_LOG_DROPIN="{(sysd / "hysteria-server.service.d/10-log-level.conf").as_posix()}"',
                'HY2_LOG_LEVEL=info',
                'HY2_LOG_LEVEL_EXPLICIT=1',
                'log_step() { :; }; log_info() { :; }; log_warn() { :; }; log_err() { :; }',
                'sysctl() { return 0; }',
                'systemctl() { return 0; }',
                'sleep() { :; }',
                patched,
                'setup_systemd',
            ]) + '\n', encoding='utf-8', newline='\n')
            res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn('net.core.rmem_max = 8388608', (sysctl_dir / '99-hysteria2.conf').read_text(encoding='utf-8'))
            self.assertIn('ExecStart=/usr/local/bin/hysteria server -c', (sysd / 'hysteria-server.service').read_text(encoding='utf-8'))
            self.assertIn('Environment=HYSTERIA_LOG_LEVEL=info', (sysd / 'hysteria-server.service.d/10-log-level.conf').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
