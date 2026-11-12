"""自定义确认框的键盘焦点（2026-11-13 修）。

旧实现焦点留在背后触发它的按钮上：键盘用户要按好几下 Tab 才摸到「确定 / 取消」，Tab 还会跑到
弹窗背后的页面，关闭后焦点也不回来。危险操作默认停在「取消」，回车不会误删。
在 node 里执行真实的 showConfirm。
"""
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
const listeners = {};
const document = {
  activeElement: null,
  addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  removeEventListener(type, fn) { listeners[type] = (listeners[type] || []).filter(f => f !== fn); },
  getElementById: id => els[id] || null,
};
function el(id) {
  const handlers = {};
  return {id, textContent: '', className: '',
    classList: {add() {}, remove() {}},
    focus() { document.activeElement = this; },
    addEventListener(type, fn) { (handlers[type] = handlers[type] || []).push(fn); },
    removeEventListener(type, fn) { handlers[type] = (handlers[type] || []).filter(f => f !== fn); },
    click() { (handlers.click || []).slice().forEach(fn => fn({target: this})); }};
}
const els = {};
for (const id of ['custom-confirm-modal', 'confirm-title', 'confirm-text', 'confirm-icon',
                  'confirm-btn-ok', 'confirm-btn-cancel']) els[id] = el(id);
const press = key => { let prevented = false;
  (listeners.keydown || []).slice().forEach(fn => fn({key, preventDefault() { prevented = true; }}));
  return prevented; };
let confirmOpen = false;
"""

CHECKS = r"""
(async () => {
  const trigger = el('trigger');
  trigger.focus();
  const danger = showConfirm({title: '卸载', isDanger: true});
  assert.strictEqual(document.activeElement, els['confirm-btn-cancel'], '危险操作没有把焦点放到「取消」');
  assert.ok(press('Tab'), 'Tab 没有被拦在弹窗里');
  assert.strictEqual(document.activeElement, els['confirm-btn-ok']);
  press('Tab');
  assert.strictEqual(document.activeElement, els['confirm-btn-cancel']);
  press('Escape');
  assert.strictEqual(await danger, false);
  assert.strictEqual(document.activeElement, trigger, '关闭后焦点没有回到触发按钮');

  const plain = showConfirm({title: '安装'});
  assert.strictEqual(document.activeElement, els['confirm-btn-ok'], '普通确认没有把焦点放到「确定」');
  els['confirm-btn-ok'].click();
  assert.strictEqual(await plain, true);
  assert.strictEqual(document.activeElement, trigger);
  console.log('OK');
})().catch(e => { console.error(e.message); process.exit(1); });
"""


@unittest.skipUnless(NODE, 'requires node')
class ConfirmFocusTest(unittest.TestCase):
    def test_focus_moves_into_the_dialog_and_comes_back(self):
        s = portal.SCRIPT
        start = s.index('function showConfirm(')
        js = HARNESS + s[start:s.index('\n}\n', start) + 3] + CHECKS
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('OK', run.stdout)


if __name__ == '__main__':
    unittest.main()
