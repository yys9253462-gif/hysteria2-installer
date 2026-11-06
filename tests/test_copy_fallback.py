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


if __name__ == '__main__':
    unittest.main()
