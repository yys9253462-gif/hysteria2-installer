"""回归测试：portal_assets.py 前端数字格式化、出站去重防原型污染、新窗口安全属性与异常恢复。"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS_SRC = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')
NODE = shutil.which('node')


class PortalAssetsHardeningTests(unittest.TestCase):
    def test_external_new_tabs_enforce_noopener_noreferrer(self):
        """所有 _blank 新标签打开链接或窗口必须切断 opener 引用（noopener / noreferrer）。"""
        self.assertIn('target="_blank" rel="noopener noreferrer">打开页面', ASSETS_SRC)
        self.assertIn("'_blank', 'noopener,noreferrer'", ASSETS_SRC)
        self.assertNotIn("awg-conf?name=' + b.getAttribute('data-awg-conf') + endpoint, '_blank')", ASSETS_SRC)
        self.assertNotIn("awg-qr.svg?name=' + b.getAttribute('data-awg-qr') + endpoint, '_blank')", ASSETS_SRC)

    def test_reboot_wait_and_awg_delete_handle_async_exceptions(self):
        """重启等待与 AWG 删除请求必须捕获异步异常，防止按钮永久锁死或静默失败。"""
        reboot_block = ASSETS_SRC[ASSETS_SRC.index('const timer = setInterval(async () => {'):
                                  ASSETS_SRC.index('// 多用户表：搜索')]
        self.assertIn('try {', reboot_block)
        self.assertIn('catch', reboot_block)

        del_block = ASSETS_SRC[ASSETS_SRC.index("awgPeerTbody.querySelectorAll('[data-awg-del]')"):
                               ASSETS_SRC.index('function renderAwgPeers') + 4000]
        self.assertIn("alert('删除失败:", del_block)

    @unittest.skipUnless(NODE, '需要 node 运行 JS 行为测试')
    def test_fmt_units_handles_nan_infinity_negative_and_render_outbound_dedup_uses_set(self):
        """fmtUnits 遇到 NaN/Infinity/负数不得渲染 NaN，出站去重不得被原型属性名吞掉。"""
        m_fmt = re.search(r'function fmtUnits\(value, units, digits\) \{.*?^\}', ASSETS_SRC, re.S | re.M)
        self.assertIsNotNone(m_fmt)
        js = (
            m_fmt.group(0) + '\n'
            'const cases = [NaN, Infinity, -Infinity, -1024, "bad", null, undefined];\n'
            'for (const v of cases) {\n'
            '  const out = fmtUnits(v, ["B/s", "KB/s", "MB/s"], [0, 1, 2]);\n'
            '  if (out !== "0 B/s") { console.error("BAD:", v, "=>", out); process.exit(1); }\n'
            '}\n'
            'console.log("FMT_OK");\n'
        )
        res = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('FMT_OK', res.stdout)

        # renderOutboundRules 去重不得使用带 Object.prototype 的普通字面量 {}
        rules_fn = ASSETS_SRC[ASSETS_SRC.index('function renderOutboundRules('):
                              ASSETS_SRC.index('function obSetModeUI(')]
        self.assertNotIn('const seen = {};', rules_fn)
        self.assertIn('new Set()', rules_fn)


if __name__ == '__main__':
    unittest.main()
