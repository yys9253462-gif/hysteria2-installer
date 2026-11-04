"""AWG 的切换协议线 / 更新按钮在请求期间禁用，防止重复提交（2026-11-04 修）。

从 portal.SCRIPT 摘出真实的按钮处理代码，用 node 在请求挂起时检查按钮状态。
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
const BTN = {disabled: false, addEventListener: (k, fn) => { handler = fn; }};
let awgCurrentLine = '2';
globalThis.prompt = () => '3';
globalThis.confirm = () => true;
globalThis.alert = () => {};
const showToast = () => {};
const loadAwgState = () => {};
let release;
const awgPost = () => new Promise(r => { release = r; });
"""

CHECKS = r"""
(async () => {
  const run = handler();
  await new Promise(r => setTimeout(r, 0));
  assert.strictEqual(BTN.disabled, true, 'button stays clickable while the request is in flight');
  release({ok: true});
  await run;
  assert.strictEqual(BTN.disabled, false, 'button not re-enabled afterwards');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


@unittest.skipUnless(NODE, 'requires node')
class AwgButtonsBusyTests(unittest.TestCase):
    def run_button(self, name):
        script = portal.SCRIPT
        start = script.index('if (%s) {' % name)
        end = script.index('\n}\n', start) + 3
        js = (HARNESS.replace('BTN', name) + script[start:end] + CHECKS.replace('BTN', name))
        return subprocess.run([NODE, '-e', 'const %s = undefined;' % '__unused' + js],
                              capture_output=True, text=True, encoding='utf-8', timeout=30)

    def test_switch_line_button(self):
        r = self.run_button('btnSwitchAwgLine')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_update_button(self):
        r = self.run_button('btnUpdateAwg')
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
