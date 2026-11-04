"""依赖安装：一个包装不上不能拖垮整批（2026-11-04 修）。

模拟 dnf 的 strict 行为：命令行里只要有一个未知包（qrencode）就整批失败、一个都不装。
执行 install.sh 里真实的 install_dependencies。
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


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class InstallDependenciesTests(unittest.TestCase):
    def test_missing_optional_package_does_not_block_critical_ones(self):
        with tempfile.TemporaryDirectory() as td:
            script = '\n'.join([
                'INST=%s' % td, 'log_step() { :; }', 'log_warn() { :; }', 'log_err() { echo "ERR $*"; }',
                # dnf：有未知包就整批失败；成功时把包名记成「已安装」
                'dnf() { shift 2; local p; for p in "$@"; do [[ "$p" == qrencode ]] && return 1; done; '
                'for p in "$@"; do touch "$INST/$p"; done; }',
                'command() { if [[ "$1" == -v ]]; then case "$2" in dnf) return 0;; apt-get|yum|apk) return 1;; '
                '*) [[ -e "$INST/$2" ]]; return;; esac; fi; builtin command "$@"; }',
                fn('install_dependencies'), 'install_dependencies; echo "RC=$?"'])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20).stdout
            installed = {p.name for p in Path(td).iterdir()}
        self.assertIn('RC=0', out, out)
        self.assertTrue({'curl', 'jq', 'openssl', 'python3'} <= installed, installed)


if __name__ == '__main__':
    unittest.main()
