"""网络层失败时，页面上的报错是中文说明（2026-11-13 修）。

断网或服务器正在重启时，浏览器的 fetch 只给「Failed to fetch」（Chrome）、「Load failed」（Safari）这类英文，
二十多个按钮照「请求异常: + 原文」弹出。SCRIPT 开头的 fetch 包装统一换成中文；主动中止的请求
（AbortError，等待服务器恢复时用到）必须原样抛出。
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
let next;
globalThis.fetch = async () => next();
"""

CHECKS = r"""
(async () => {
  for (const original of ['Failed to fetch', 'Load failed']) {
    next = () => { throw new TypeError(original); };
    const err = await fetch('/x').then(() => null, e => e);
    assert(err instanceof TypeError, String(err));
    assert(err.message.includes('无法连接服务器'), err.message);
  }
  next = () => { throw new DOMException('The operation was aborted.', 'AbortError'); };
  const aborted = await fetch('/x').then(() => null, e => e);
  assert.strictEqual(aborted.name, 'AbortError');
  next = () => new Response('{"ok":true}');
  assert.deepStrictEqual(await (await fetch('/x')).json(), {ok: true});
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


@unittest.skipUnless(NODE, 'requires node')
class NetworkErrorMessageTest(unittest.TestCase):
    def test_network_failures_read_as_chinese_and_aborts_pass_through(self):
        script = portal.SCRIPT
        prelude = script[:script.index('// 全局高颜值 Promise 确认框与 Toast 机制')]
        run = subprocess.run([NODE, '-e', HARNESS + prelude + CHECKS], capture_output=True, text=True,
                             encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
