"""`bash install.sh info` 在凭据文件损坏时给出可操作的提示（2026-11-04 修）。"""
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


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class InfoCorruptAccessTests(unittest.TestCase):
    def info(self, content):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'portal-access.json').write_text(content)
            script = '\n'.join(['set -eo pipefail', 'HY2_DIR=%s' % td, 'log_err() { echo "ERR $*"; }',
                                fn('show_client_configs'), 'show_client_configs || echo "RC=$?"'])
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                  encoding='utf-8', timeout=20).stdout

    def test_truncated_file_points_to_refresh(self):
        out = self.info('{"url": "https://a')
        self.assertIn('refresh-page', out)
        self.assertIn('RC=1', out)

    def test_missing_fields_do_not_print_null(self):
        out = self.info('{"url": "https://a.example/t/"}')
        self.assertNotIn('null', out)
        self.assertIn('RC=1', out)


if __name__ == '__main__':
    unittest.main()
