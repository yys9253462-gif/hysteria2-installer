"""do_upgrade.sh 的 Hysteria 重启先清失败计数（2026-11-06 修）。

新核心起不来时会回滚再重启；不清计数就容易撞上 StartLimitBurst，旧核心也被拒绝启动。
从 install.sh 里摘出生成的 do_upgrade.sh 中真实的 hy2_restarted_ok 执行。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
UPGRADE = re.search(r"cat > \"\$HY2_DIR/do_upgrade.sh\" <<'EOUG'\n(.*?)\nEOUG\n", SRC, re.S).group(1)


@unittest.skipUnless(BASH, 'requires bash')
class DoUpgradeRestartTests(unittest.TestCase):
    def test_restart_helper_resets_the_start_limit_first(self):
        body = re.search(r'    hy2_restarted_ok\(\) \{\n.*?\n    \}\n', UPGRADE, re.S).group(0)
        with tempfile.TemporaryDirectory() as td:
            script = '\n'.join(['systemctl() { echo "$1" >> %s/calls; return 0; }' % td, 'sleep() { :; }',
                                body, 'hy2_restarted_ok; echo "RC=$?"'])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20).stdout
            calls = (Path(td) / 'calls').read_text().split()
        self.assertIn('RC=0', out)
        self.assertLess(calls.index('reset-failed'), calls.index('restart'))


if __name__ == '__main__':
    unittest.main()
