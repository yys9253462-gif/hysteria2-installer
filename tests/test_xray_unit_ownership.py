"""不覆盖不归本工具管理的 xray.service（2026-11-04 修）。

走真实的 /install-xray 处理函数：单元是官方脚本写的时回 409，且不下载、不替换二进制。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

OFFICIAL = ('[Service]\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n')


class XrayUnitOwnershipTests(unittest.TestCase):
    def test_detects_foreign_and_owned_units(self):
        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / 'xray.service'
            self.assertFalse(portal.xray_unit_foreign(unit))
            unit.write_text(OFFICIAL)
            self.assertTrue(portal.xray_unit_foreign(unit))
            unit.write_text(portal.XRAY_UNIT_CONTENT)
            self.assertFalse(portal.xray_unit_foreign(unit))




if __name__ == '__main__':
    unittest.main()
