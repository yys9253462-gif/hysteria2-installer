"""is_valid_port 拒收前导零与越界值（2026-11-06 修）。"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
FN = re.search(r'^is_valid_port\(\) \{\n.*?^\}', SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class IsValidPortTests(unittest.TestCase):
    def check(self, value):
        r = subprocess.run([BASH, '-c', FN + '\nis_valid_port "%s" && echo Y || echo N' % value],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.stderr

    def test_values(self):
        for value, want in (('443', 'Y'), ('1', 'Y'), ('65535', 'Y'), ('0', 'N'), ('65536', 'N'),
                            ('0443', 'N'), ('020000', 'N'), ('08', 'N'), ('09', 'N'), ('', 'N'),
                            ('abc', 'N'), ('-1', 'N'), ('00000000000000000000443', 'N')):
            with self.subTest(value=value):
                out, err = self.check(value)
                self.assertEqual(out, want)
                self.assertNotIn('value too great', err)


if __name__ == '__main__':
    unittest.main()
