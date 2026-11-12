"""菜单「查看实时运行日志」同时跟踪核心与门户（2026-11-13 修）。

门户是 Hy2 的鉴权后端，用户连不上时原因常在它那边（鉴权失败、收回失败、计量异常）；
旧实现只跟 hysteria-server 的日志。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(shutil.which('bash'), 'requires bash')
class ViewLogsTest(unittest.TestCase):
    def test_core_and_portal_logs_are_followed_together(self):
        script = '\n'.join(['require_installed() { :; }', 'CYAN=; PLAIN=',
                            'journalctl() { printf "ARG %s\\n" "$@"; }', fn('view_logs'), 'view_logs'])
        out = subprocess.run([shutil.which('bash'), '-c', script], capture_output=True, text=True,
                             encoding='utf-8', timeout=20).stdout
        args = [line[4:] for line in out.splitlines() if line.startswith('ARG ')]
        units = [args[i + 1] for i, arg in enumerate(args) if arg == '-u']
        self.assertEqual(sorted(units), ['hysteria-portal', 'hysteria-server'])
        self.assertIn('-f', args)


if __name__ == '__main__':
    unittest.main()
