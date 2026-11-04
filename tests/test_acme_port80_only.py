"""内置 ACME（HTTP-01）只要 TCP 80 空闲；443 被占（如 Reality）不再挡住它（2026-11-04 修）。"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class AcmePort80OnlyTests(unittest.TestCase):
    def squatting(self, busy):
        script = '\n'.join([
            'port_owner() { case " %s " in *" $2 "*) echo xray;; esac; }' % ' '.join(map(str, busy)),
            fn('detect_webserver_squatting'),
            'detect_webserver_squatting; echo "RC=$? B=$ACRE_PORT_BLOCKER"'])
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=20).stdout

    def test_only_443_busy_is_not_squatting(self):
        self.assertIn('RC=1', self.squatting([443]))

    def test_80_busy_is_squatting(self):
        out = self.squatting([80, 443])
        self.assertIn('RC=0', out)
        self.assertIn('TCP 80', out)


if __name__ == '__main__':
    unittest.main()
