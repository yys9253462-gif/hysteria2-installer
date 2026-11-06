"""HY2_CUSTOM_INSECURE 归一成 true / false 后再写进 JSON（2026-11-06 修）。"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


@unittest.skipUnless(BASH, 'requires bash')
class CustomInsecureTests(unittest.TestCase):
    def norm(self, value):
        block = re.search(r'        case "\$\{HY2_CUSTOM_INSECURE:-false\}" in\n.*?\n        esac\n', SRC, re.S).group(0)
        script = 'HY2_CUSTOM_INSECURE=%s\n%s\necho "V=$IS_INSECURE"' % (value, block)
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=10).stdout.strip()

    def test_values(self):
        for value, want in (('yes', 'true'), ('True', 'true'), ('1', 'true'), ('true', 'true'),
                            ('no', 'false'), ('0', 'false'), ("''", 'false'), ('garbage', 'false')):
            with self.subTest(value=value):
                self.assertEqual(self.norm(value), 'V=' + want)


if __name__ == '__main__':
    unittest.main()
