"""回归测试：/api/v1/capabilities 必须真实解析出非空 PORTAL_VERSION（不被前 80 行截断），且文件不可读时回落模块常量。"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class CapabilitiesPortalVersionLiveTests(unittest.TestCase):
    def _extract_version_block(self) -> str:
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        start = src.index("if sub == 'capabilities':")
        anchor = src.index("portal_version =", start)
        anchor = src.rfind('\n', 0, anchor) + 1
        end = src.index("return self.reply_json(200, {", anchor)
        return src[anchor:end]

    def test_capabilities_actually_extracts_nonempty_portal_version(self):
        """按 /api/v1/capabilities 里的真实解析逻辑执行，必须读出等于 portal.PORTAL_VERSION 的非空版本。"""
        block = self._extract_version_block()
        lines = block.splitlines()
        indent = min(len(ln) - len(ln.lstrip()) for ln in lines if ln.strip())
        dedented = '\n'.join(ln[indent:] if len(ln) >= indent else ln for ln in lines)

        ns = {
            'Path': Path,
            '__file__': str(ROOT / 'portal.py'),
            'PORTAL_VERSION': portal.PORTAL_VERSION,
        }
        exec(compile(dedented, '<capabilities_portal_version>', 'exec'), ns)
        self.assertEqual(ns['portal_version'], portal.PORTAL_VERSION,
                         'capabilities 版本解析逻辑被行号截断，未读出 PORTAL_VERSION')
        self.assertRegex(ns['portal_version'], r'^\d+\.\d+$')

    def test_capabilities_falls_back_to_constant_when_file_unreadable(self):
        """当 __file__ 指向不可读文件时，仍应回落到模块常量 PORTAL_VERSION 而非空串。"""
        block = self._extract_version_block()
        lines = block.splitlines()
        indent = min(len(ln) - len(ln.lstrip()) for ln in lines if ln.strip())
        dedented = '\n'.join(ln[indent:] if len(ln) >= indent else ln for ln in lines)

        ns = {
            'Path': Path,
            '__file__': str(ROOT / '__nonexistent_portal_file__.py'),
            'PORTAL_VERSION': portal.PORTAL_VERSION,
        }
        exec(compile(dedented, '<capabilities_portal_version_fallback>', 'exec'), ns)
        self.assertEqual(ns['portal_version'], portal.PORTAL_VERSION)


if __name__ == '__main__':
    unittest.main()
