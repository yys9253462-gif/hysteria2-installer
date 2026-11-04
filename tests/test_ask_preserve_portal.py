"""portal-access.json 缺失时仍询问并默认沿用门户（2026-11-04 修）。"""
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
class AskPreservePortalTests(unittest.TestCase):
    def ask(self, files, answer=''):
        with tempfile.TemporaryDirectory() as td:
            for f in files:
                (Path(td) / f).write_text('{}')
            script = '\n'.join(['HY2_DIR=%s' % td, 'YELLOW= PLAIN=', 'log_warn() { :; }',
                                fn('ask_preserve_portal'), 'ask_preserve_portal; echo "P=$PRESERVE_PORTAL"'])
            return subprocess.run([BASH, '-c', script], input=answer, capture_output=True,
                                  text=True, encoding='utf-8', timeout=20).stdout

    def test_missing_access_file_still_preserves_by_default(self):
        self.assertIn('P=1', self.ask(['portal.json']))

    def test_explicit_no_rebuilds(self):
        self.assertIn('P=0', self.ask(['portal.json'], 'n\n'))

    def test_fresh_node_does_not_ask(self):
        self.assertIn('P=0', self.ask([]))


if __name__ == '__main__':
    unittest.main()
