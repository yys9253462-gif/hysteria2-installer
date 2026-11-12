"""alpine2debian.sh 的提示里的版本跟着 --suite 走（2026-11-13 修）。

旧实现写死 Debian 12：用 --suite trixie 时清盘确认说「安装 Debian 12（trixie）」，装完的核验说明还让人
去对 Debian GNU/Linux 12 (bookworm)，像是装错了。截取清盘确认与最后核验说明两行实际执行。
"""
import shutil
import subprocess
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'alpine2debian.sh').read_text(encoding='utf-8')
SH = shutil.which('sh') or shutil.which('bash')


def line_starting(prefix):
    start = SRC.index(prefix)
    return SRC[start:SRC.index('\n', start) + 1]


def messages_script():
    label = ''
    marker = '# 提示里的版本跟着 --suite 走'
    if marker in SRC:
        start = SRC.index(marker)
        label = SRC[start:SRC.index('esac\n', start) + 5]
    return (label + line_starting('warn "即将清空磁盘')
            + line_starting("printf '    4. 验证"))


@unittest.skipUnless(SH, 'requires sh')
class SuiteLabelTest(unittest.TestCase):
    def run_messages(self, suite):
        script = 'warn() { echo "$*"; }\nDISK=/dev/vdb\nDEBIAN_SUITE="$1"\n' + messages_script()
        return subprocess.run([SH, '-c', script, 'sh', suite], capture_output=True, text=True,
                              encoding='utf-8', timeout=20).stdout

    def test_trixie_is_named_debian_13_everywhere(self):
        out = self.run_messages('trixie')
        self.assertEqual(out.count('Debian GNU/Linux 13 (trixie)'), 2, out)
        self.assertNotIn('bookworm', out)
        self.assertNotIn('Debian 12', out)

    def test_default_suite_still_reads_debian_12(self):
        self.assertEqual(self.run_messages('bookworm').count('Debian GNU/Linux 12 (bookworm)'), 2)


if __name__ == '__main__':
    unittest.main()
