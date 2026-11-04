"""字节数显示先取整再定单位，不再出现「1024.0 KB」（2026-11-04 修）。后端与弹窗 JS 同一规则。"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

CASES = {1023: '1023 B', 1024 ** 2 - 1: '1.00 MB', 1024 ** 3 - 1: '1.00 GB', 1024 ** 4 - 1: '1.00 TB',
         1536: '1.5 KB'}


class FormatBytesRoundingTests(unittest.TestCase):
    def test_backend(self):
        for value, text in CASES.items():
            with self.subTest(value=value):
                self.assertEqual(portal.format_bytes(value), text)

    @unittest.skipUnless(shutil.which('node'), 'requires node')
    def test_modal_js(self):
        s = portal.SCRIPT
        i = s.index('const fmtBytes = v => {')
        js = s[i:s.index('};', i) + 2] + '\nfor (const v of [%s]) console.log(fmtBytes(v));' % ','.join(
            str(v) for v in (1024 ** 2 - 1, 1024 ** 3 - 1, 1024 ** 4 - 1))
        out = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=20).stdout.split('\n')
        self.assertEqual(out[:3], ['1.00 MB', '1.00 GB', '1.00 TB'])


if __name__ == '__main__':
    unittest.main()
