"""回归测试：setup_portal、setup_cert_selfheal 单元文件与 warp_migrate_legacy_outbound 必须走同目录临时文件原子替换。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
BASH = shutil.which('bash')


def _extract_fn(source: str, name: str) -> str:
    start = source.index('\n' + name + '() {') + 1
    depth = 0
    for idx in range(source.index('{', start), len(source)):
        ch = source[idx]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return source[start:idx + 1]
    raise AssertionError(name + ' 未闭合')


@unittest.skipUnless(BASH, '需要 bash 环境')
class PortalSelfhealAndWarpMigrateAtomicTests(unittest.TestCase):
    def test_setup_portal_and_selfheal_units_are_written_atomically(self):
        """hysteria-portal.service 与 hy2-cert-selfheal.{service,timer,path} 不得裸 cat > 覆写。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        sp = _extract_fn(src, 'setup_portal')
        self.assertNotIn('cat > /etc/systemd/system/hysteria-portal.service', sp)
        self.assertIn('mv -f', sp)

        sc = _extract_fn(src, 'setup_cert_selfheal')
        for unit in ('hy2-cert-selfheal.service', 'hy2-cert-selfheal.timer', 'hy2-cert-selfheal.path'):
            self.assertNotIn(f'cat > /etc/systemd/system/{unit}', sc, f'{unit} 仍裸覆写')
        self.assertIn('mv -f', sc)

    def test_warp_migrate_legacy_outbound_replaces_literally_and_atomically(self):
        """warp_migrate_legacy_outbound 不得用 sed -i，且能把 127.0.0.1:40000 原子替换为目标地址。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = _extract_fn(src, 'warp_migrate_legacy_outbound')
        self.assertNotIn('sed -i', fn, 'warp_migrate_legacy_outbound 仍使用非原子且易被 &/| 注入的 sed -i')

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('outbounds:\n  - name: warp\n    socks5:\n      addr: 127.0.0.1:40000\n', encoding='utf-8')
            script = Path(td) / 'run_migrate.sh'
            script.write_text('\n'.join([
                'set -euo pipefail',
                f'HY2_CONFIG="{cfg.as_posix()}"',
                'systemctl() { return 0; }',
                fn,
                'warp_migrate_legacy_outbound "127.0.0.1:19898"',
            ]) + '\n', encoding='utf-8', newline='\n')
            res = subprocess.run([BASH, str(script)], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            updated = cfg.read_text(encoding='utf-8')
            self.assertIn('addr: 127.0.0.1:19898', updated)
            self.assertNotIn('127.0.0.1:40000', updated)


if __name__ == '__main__':
    unittest.main()
