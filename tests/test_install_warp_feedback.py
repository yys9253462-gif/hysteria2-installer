"""一键安装 WARP 失败时提示里写原因，而不是响应原文（2026-11-12 修）。

旧实现 `!res.ok` 时把 `await res.text()` 原样拼进提示：服务端回的是
{"ok": false, "error": "执行异常: …"}，用户看到的就是这一串 JSON；反代回 502 时是整页 HTML。
从 portal.SCRIPT 摘出真实的按钮处理代码与全局 Response.json 补丁，用 node 执行。
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
const toasts = [];
globalThis.showToast = (msg, type) => toasts.push([type, msg]);
globalThis.confirm = () => true;
globalThis.showConfirm = async () => true;
let handler;
const btnInstallWarp = {disabled: false, textContent: '⚡ 一键安装 WARP',
                        addEventListener: (k, fn) => { handler = fn; }};
let checked = 0;
async function checkWarpStatus() { checked += 1; }
const location = {pathname: '/t/'};
"""

CHECKS = r"""
(async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ok: false, error: '执行异常: wgcf 下载失败'}),
                                              {status: 500});
  await handler();
  assert.deepStrictEqual(toasts.pop(), ['error', '执行异常: wgcf 下载失败']);
  globalThis.fetch = async () => new Response('<html><body>' + 'x'.repeat(4000) + '</body></html>', {status: 502});
  await handler();
  const [type, msg] = toasts.pop();
  assert.strictEqual(type, 'error');
  assert.ok(msg.includes('502') && msg.length < 260, msg.length + ': ' + msg.slice(0, 80));
  globalThis.fetch = async () => new Response(JSON.stringify({ok: true, message: 'WARP 通道安装完成'}));
  await handler();
  assert.deepStrictEqual(toasts.pop(), ['success', 'WARP 通道安装完成']);
  assert.strictEqual(checked, 1);
  assert.strictEqual(btnInstallWarp.disabled, false);
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


@unittest.skipUnless(NODE, 'requires node')
class InstallWarpFeedbackTests(unittest.TestCase):
    def test_failure_toast_carries_the_reason_not_the_raw_body(self):
        script = portal.SCRIPT
        prelude = script[:script.index('// 全局高颜值 Promise 确认框与 Toast 机制')]
        start = script.index('\nif (btnInstallWarp) {') + 1   # 顶层那段；checkWarpStatus 里也有同名判断
        block = script[start:script.index('\n}\n', start) + 3]
        r = subprocess.run([NODE, '-e', prelude + HARNESS + block + CHECKS],
                           capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
