"""用户表的分页按钮有可读名称，当前页有标注（2026-11-13 修）。

分页按钮由脚本生成：「‹」「›」读屏念出来是符号名，页码按钮也听不出哪一页是当前页。
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')

HARNESS = r"""
let made = [];
const el = tag => {
  const attrs = {}, listeners = {};
  return {tagName: tag, attrs, listeners, style: {}, dataset: {}, className: '', disabled: false,
          setAttribute(k, v) { attrs[k] = String(v); }, getAttribute(k) { return k in attrs ? attrs[k] : null; },
          addEventListener(t, f) { (listeners[t] = listeners[t] || []).push(f); }};
};
const rows = Array.from({length: 45}, (_, i) => Object.assign(el('TR'), {dataset: {state: 'active', search: 'u' + i}}));
const tbody = Object.assign(el('TBODY'), {querySelectorAll: () => rows});
const pager = Object.assign(el('DIV'), {appendChild(c) { made.push(c); return c; }});
Object.defineProperty(pager, 'textContent', {get: () => '', set: () => { made = []; }});
const ids = {'user-tbody': tbody, 'user-pager': pager};
const document = {getElementById: id => ids[id] || null, createElement: tag => el(String(tag).toUpperCase())};
"""

CHECKS = r"""
const snapshot = () => made.filter(m => m.tagName === 'BUTTON')
  .map(b => [b.textContent, b.attrs['aria-label'] || null, b.attrs['aria-current'] || null]);
const first = snapshot();
const next = made.filter(m => m.tagName === 'BUTTON').pop();
next.listeners.click[0]();
console.log(JSON.stringify({first, second: snapshot()}));
"""


@unittest.skipUnless(NODE, 'requires node')
class UserPagerNamesTest(unittest.TestCase):
    def test_pager_buttons_are_named_and_mark_the_current_page(self):
        script = portal.SCRIPT
        start = script.index('(function initUserTable() {')
        end = script.index('\n})();\n', start) + len('\n})();\n')
        run = subprocess.run([NODE, '-e', HARNESS + script[start:end] + CHECKS], capture_output=True,
                             text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertEqual(result['first'], [['‹', '上一页', None], ['1', '第 1 页', 'page'], ['2', '第 2 页', None],
                                           ['3', '第 3 页', None], ['›', '下一页', None]])
        self.assertEqual([b[2] for b in result['second']], [None, None, 'page', None, None])


if __name__ == '__main__':
    unittest.main()
