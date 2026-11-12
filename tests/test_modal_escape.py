"""Esc 关闭专属连接 / 代理详情弹窗；确认框开着时不抢它的 Esc（2026-11-06 加）。"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')

HARNESS = r"""
const assert = require('assert');
const mk = () => { const c = new Set(); return {classList: {add: x => c.add(x), remove: x => c.delete(x), contains: x => c.has(x)}}; };
const uModal = mk(), proxyModal = mk(), confirmModal = mk();
const keyHandlers = [];
globalThis.document = {
  addEventListener: (k, fn) => { if (k === 'keydown') keyHandlers.push(fn); },
  querySelector: sel => (sel === '#custom-confirm-modal.show' && confirmModal.classList.contains('show')) ? confirmModal : null,
};
function closeProxyModal() { proxyModal.classList.remove('show'); }
function restoreModalFocus() {}
"""


@unittest.skipUnless(NODE, 'requires node')
class ModalEscapeTests(unittest.TestCase):
    def test_escape_closes_open_modal_unless_confirm_is_up(self):
        s = portal.SCRIPT
        start = s.index('function closeUserModal() {')
        end = s.index('\n});\n', s.index("if (e.key !== 'Escape'", start)) + 5
        checks = r"""
const press = () => keyHandlers.forEach(fn => fn({key: 'Escape'}));
uModal.classList.add('show'); press();
assert(!uModal.classList.contains('show'), 'Esc 没有关闭专属连接弹窗');
proxyModal.classList.add('show'); confirmModal.classList.add('show'); press();
assert(proxyModal.classList.contains('show'), '确认框开着时不该关掉底下的弹窗');
confirmModal.classList.remove('show'); press();
assert(!proxyModal.classList.contains('show'), 'Esc 没有关闭代理详情弹窗');
"""
        js = HARNESS + s[start:end].replace('if (uModalClose)', 'if (false)').replace('if (uModal) {\n  uModal.addEventListener', 'if (false) {\n  uModal.addEventListener') + checks
        r = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
