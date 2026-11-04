"""门户文件包下载失败时报出是哪个文件（2026-11-04 修）。"""
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
class PortalFetchErrorTests(unittest.TestCase):
    def test_failed_file_is_named(self):
        with tempfile.TemporaryDirectory() as td:
            script = '\n'.join([
                'PORTAL_FILES="portal.py portal_assets.py"', 'METER_FILES="m.py"', 'PORTAL_FETCH_REF=x',
                'curl() { case "$*" in *portal_assets*) return 22;; esac; local o; while [[ $# -gt 0 ]]; do '
                '[[ "$1" == -o ]] && o="$2"; shift; done; : > "$o"; }',
                fn('portal_fetch_files'),
                'portal_fetch_files %s https://cdn.example raw; echo "RC=$? ERR=$PORTAL_FETCH_FILES_ERR"' % td])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                 encoding='utf-8', timeout=20).stdout
        self.assertIn('RC=1', out)
        self.assertIn('ERR=下载 portal_assets.py 失败', out)


if __name__ == '__main__':
    unittest.main()
