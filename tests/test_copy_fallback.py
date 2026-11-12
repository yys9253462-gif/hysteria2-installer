"""复制按钮在没有 navigator.clipboard 时（http / 权限被拒）走 execCommand 兜底（2026-11-06 修）。

旧实现：管理页对 <div> 字段什么都没选中却提示「已选中」；用户页静默失败。
从 SCRIPT / USER_SCRIPT 摘出真实的 [data-copy] 处理代码，用 node 执行。
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
let handler;
const button = {dataset: {copy: 'f'}, textContent: '复制 Key', addEventListener: (k, fn) => { handler = fn; }};
const field = {textContent: 'SECRET-KEY'};   // <div>：没有 .select
const status = {textContent: ''};
const copied = [];
globalThis.navigator = {};                   // http：没有 clipboard
globalThis.setTimeout = () => 0;
globalThis.document = {
  querySelectorAll: sel => sel === '[data-copy]' ? [button] : [],
  getElementById: id => id === 'f' ? field : (id === 'copy-status' ? status : null),
  createElement: () => ({style: {}, value: '', select() {}, remove() {}}),
  body: {appendChild(el) { globalThis.__ta = el; }},
  execCommand: cmd => { copied.push(globalThis.__ta.value); return true; },
};
"""

TIMERS = r"""
const assert = require('assert');
let handler;
let nextTimer = 0;
const timers = new Map();
globalThis.setTimeout = fn => { timers.set(++nextTimer, fn); return nextTimer; };
globalThis.clearTimeout = id => { timers.delete(id); };
const flush = () => { const due = [...timers.values()]; timers.clear(); due.forEach(fn => fn()); };
// node 自带只读的 navigator 访问器，直接赋值不生效。
const setClipboard = clipboard => Object.defineProperty(globalThis, 'navigator',
  {value: {clipboard}, configurable: true, writable: true});
globalThis.alert = () => {};
const button = {dataset: {copy: 'f'}, textContent: '复制直链', addEventListener: (k, fn) => { handler = fn; }};
const field = {value: 'hysteria2://fixture', select() {}, focus() {}};
globalThis.document = {
  querySelectorAll: sel => sel === '[data-copy]' ? [button] : [],
  getElementById: id => id === 'f' ? field : null,
  createElement: () => ({style: {}, value: '', select() {}, remove() {}}),
  body: {appendChild() {}},
  execCommand: () => false,
};
"""

CHECKS = r"""
(async () => {
  await handler();
  assert.deepStrictEqual(copied, ['SECRET-KEY'], 'execCommand 兜底没有复制到内容');
  assert(button.textContent.includes('已复制'), '按钮没有反馈：' + button.textContent);
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


@unittest.skipUnless(NODE, 'requires node')
class CopyFallbackTests(unittest.TestCase):
    def run_block(self, script):
        start = script.index("document.querySelectorAll('[data-copy]').forEach(button => {")
        end = script.index('\n});\n', start) + 5
        r = subprocess.run([NODE, '-e', HARNESS + script[start:end] + CHECKS],
                           capture_output=True, text=True, encoding='utf-8', timeout=30)
        return r

    def test_admin_page_copy_falls_back(self):
        r = self.run_block(portal.SCRIPT)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_user_page_copy_falls_back(self):
        r = self.run_block(portal.USER_SCRIPT)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_clicking_again_before_the_label_resets_does_not_stick(self):
        """恢复前再点一下，按钮文字最后仍回到原文（2026-11-12 修）。

        旧实现每次点击都把当前文字当原文：第二下记成「已复制 ✓」/「已选中，请按 Ctrl+C」，
        两个恢复定时器先后触发后，按钮永远停在那句话上。用户分享页与管理弹窗各验一次。
        """
        user_start = portal.USER_SCRIPT.index("document.querySelectorAll('[data-copy]').forEach(button => {")
        user_block = portal.USER_SCRIPT[user_start:portal.USER_SCRIPT.index('\n});\n', user_start) + 5]
        helper_start = portal.SCRIPT.index('function copyWithFeedback(')
        helper = portal.SCRIPT[helper_start:portal.SCRIPT.index('\n}\n', helper_start) + 3]
        source = TIMERS + user_block + helper + r"""
(async () => {
  const settle = () => new Promise(r => setImmediate(r));
  const cases = [[{writeText: async () => {}}, '已复制 ✓'],
                 [{writeText: async () => { throw new Error('denied'); }}, '已选中，请按 Ctrl+C']];
  for (const [clip, pressed] of cases) {
    setClipboard(clip);
    button.textContent = '复制直链';
    delete button.dataset.orig;
    await handler();
    assert.strictEqual(button.textContent, pressed);
    await handler();
    flush();
    assert.strictEqual(button.textContent, '复制直链', 'user page label stuck');
  }
  setClipboard({writeText: async () => {}});
  const modalBtn = {dataset: {}, textContent: '复制订阅'};
  copyWithFeedback('x', modalBtn, '已复制 ✓');
  await settle();
  copyWithFeedback('x', modalBtn, '已复制 ✓');
  await settle();
  flush();
  assert.strictEqual(modalBtn.textContent, '复制订阅', 'modal label stuck');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        r = subprocess.run([NODE, '-e', source], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
