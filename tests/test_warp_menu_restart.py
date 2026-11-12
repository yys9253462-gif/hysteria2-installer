"""菜单装 WARP 时只在确实有旧版 40000 出站时才改配置、重启 Hysteria（2026-11-13 修）。

旧实现无条件 `systemctl restart hysteria-server`：新装机的配置里根本没有 127.0.0.1:40000，
装一次 WARP 就把所有在线用户断开一次。这里执行 install_warp_local_proxy 的第 7 步本身。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


def migration_step():
    body = fn('install_warp_local_proxy')
    step = body[body.index('    # 7.'):body.index('    # 8.')]
    helper = fn('warp_migrate_legacy_outbound') if 'warp_migrate_legacy_outbound() {' in SRC else ''
    return helper + '\n' + step


@unittest.skipUnless(shutil.which('bash'), 'requires bash')
class WarpMenuRestartTest(unittest.TestCase):
    def run_step(self, config_text):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'config.yaml'
            config.write_text(config_text, encoding='utf-8')
            script = '\n'.join([
                'HY2_CONFIG="$1"; WARP_SOCKS_ADDR=127.0.0.1:19898',
                'systemctl() { echo "SYSTEMCTL $*"; }',
                migration_step()])
            run = subprocess.run([shutil.which('bash'), '-c', script, 'bash', str(config)],
                                 capture_output=True, text=True, encoding='utf-8', timeout=30)
            return run.stdout, config.read_text(encoding='utf-8')

    def test_current_config_is_left_alone(self):
        text = 'outbounds:\n  - name: warp\n    socks5:\n      addr: 127.0.0.1:19898\n'
        out, after = self.run_step(text)
        self.assertNotIn('restart hysteria-server', out, '配置没变也重启了 Hysteria，在线用户全部断开')
        self.assertEqual(after, text)

    def test_legacy_outbound_is_migrated_and_core_restarted(self):
        out, after = self.run_step('outbounds:\n  - name: warp\n    socks5:\n      addr: 127.0.0.1:40000\n')
        self.assertIn('addr: 127.0.0.1:19898', after)
        self.assertNotIn('127.0.0.1:40000', after)
        calls = [line for line in out.splitlines() if line.startswith('SYSTEMCTL')]
        self.assertEqual(calls, ['SYSTEMCTL reset-failed hysteria-server', 'SYSTEMCTL restart hysteria-server'])


if __name__ == '__main__':
    unittest.main()
