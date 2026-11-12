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

    def run_apt(self, lock_free_after_wait):
        """apt-get 打桩：锁被 unattended-upgrades 占着，只有带了等锁选项才等得到（2026-11-12 修）。"""
        with tempfile.TemporaryDirectory() as td:
            script = '\n'.join([
                'INST=%s' % td, 'log_step() { :; }', 'log_warn() { :; }', 'log_err() { echo "ERR $*"; }',
                'apt-get() { echo "apt-get $*" >> "$INST/.calls"; local waits=0 p; '
                '[[ "$*" == *"DPkg::Lock::Timeout="* ]] && waits=1; '
                'if [[ "$waits" == 0 || %s == 0 ]]; then echo "E: Could not get lock /var/lib/dpkg/lock-frontend" >&2; return 100; fi; '
                '[[ " $* " == *" install "* ]] || return 0; '
                'for p in "$@"; do [[ "$p" == -* || "$p" == install || "$p" == DPkg::* ]] || touch "$INST/$p"; done; }'
                % ('1' if lock_free_after_wait else '0'),
                'command() { if [[ "$1" == -v ]]; then case "$2" in apt-get) return 0;; dnf|yum|apk) return 1;; '
                '*) [[ -e "$INST/$2" ]]; return;; esac; fi; builtin command "$@"; }',
                fn('install_dependencies'), 'install_dependencies; echo "RC=$?"'])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20).stdout
            calls = (Path(td) / '.calls').read_text()
        return out, calls

    def test_apt_waits_for_the_dpkg_lock_instead_of_failing(self):
        out, calls = self.run_apt(lock_free_after_wait=True)
        self.assertIn('RC=0', out, out + calls)
        for line in calls.splitlines():
            self.assertIn('-o DPkg::Lock::Timeout=300', line)

    def test_lock_still_held_after_waiting_says_why(self):
        out, _ = self.run_apt(lock_free_after_wait=False)
        self.assertIn('RC=1', out)
        self.assertIn('Could not get lock', out)

    def test_portal_warp_installer_waits_for_the_lock_too(self):
        portal_src = (ROOT / 'portal.py').read_text(encoding='utf-8').replace('\r\n', '\n')
        start = portal_src.index('for t in curl jq; do')
        loop = portal_src[start:portal_src.index('\ndone\n', start) + 6]
        with tempfile.TemporaryDirectory() as td:
            script = '\n'.join([
                'apt-get() { echo "apt-get $*" >> %s/calls; }' % td,
                'command() { if [[ "$1" == -v ]]; then [[ "$2" == apt-get ]]; return; fi; builtin command "$@"; }',
                loop])
            subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20)
            calls = (Path(td) / 'calls').read_text().splitlines()
        self.assertTrue(calls)
        for line in calls:
            self.assertIn('-o DPkg::Lock::Timeout=', line)


if __name__ == '__main__':
    unittest.main()
