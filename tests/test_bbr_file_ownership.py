"""门户写的 BBR 文件带归属标记，卸载据此删除（2026-11-03 修）。

旧实现写的 /etc/modules-load.d/bbr.conf 与 /etc/sysctl.d/99-bbr.conf 没有任何标记，
卸载也不删：卸载重启后机器仍加载 BBR 模块、套用 tcp_notsent_lowat 等参数。
这里锁住两件事：门户与 install.sh 用同一个标记；卸载段落只删带标记的文件。
"""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


@unittest.skipUnless(BASH, 'requires bash')
class BbrFileOwnershipTests(unittest.TestCase):
    def test_uninstall_removes_only_marked_bbr_files(self):
        block = re.search(r'\n(        local bbr_file\n.*?\n        done\n)', SRC, re.S).group(1)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            ours, theirs = td / 'bbr.conf', td / '99-bbr.conf'
            ours.write_text(portal.BBR_FILE_MARKER + '\ntcp_bbr\n', encoding='utf-8')
            theirs.write_text('net.ipv4.tcp_congestion_control = bbr\n', encoding='utf-8')
            block = (block.replace('/etc/modules-load.d/bbr.conf', bash_path(ours))
                          .replace('/etc/sysctl.d/99-bbr.conf', bash_path(theirs)))
            subprocess.run([BASH, '-c', 'f() {\n' + block + '}\nf'], capture_output=True,
                           text=True, encoding='utf-8', timeout=20)
            self.assertFalse(ours.exists(), '带标记的 BBR 文件没有被卸载删除')
            self.assertTrue(theirs.exists(), '没有标记的文件被误删')

    def test_portal_marker_matches_install_sh(self):
        self.assertIn("'%s'" % portal.BBR_FILE_MARKER, SRC)


if __name__ == '__main__':
    unittest.main()
