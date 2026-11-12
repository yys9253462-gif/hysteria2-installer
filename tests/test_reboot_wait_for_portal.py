"""重启服务器后等门户真正恢复再刷新（2026-11-12 修）。

确认框承诺「就绪后重连」，旧实现却在 25 秒倒计时结束时无条件 location.reload()；
VPS 重启常要 30~90 秒，多半落在浏览器的「无法访问此网站」错误页。
从 portal.SCRIPT 摘出真实的重启按钮处理与等待函数，用 node 快进定时器。
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
const realSetTimeout = setTimeout;
globalThis.setTimeout = fn => realSetTimeout(fn, 0);
const intervals = [];
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = () => {};
const alerts = [];
globalThis.alert = m => alerts.push(String(m));
let reloads = 0, polls = 0, pollsAtReload = -1;
const location = {pathname: '/fixture/', reload() { reloads++; pollsAtReload = polls; }};
let handler;
const btnRebootServer = {addEventListener: (k, fn) => { handler = fn; }, disabled: false, textContent: 'x'};
const showConfirm = async () => true;
let answers = [];
globalThis.fetch = async url => {
  if (url.endsWith('reboot-server')) return new Response(JSON.stringify({ok: true}));
  polls++;
  const next = answers.length ? answers.shift() : 'down';
  if (next === 'down') throw new TypeError('Failed to fetch');
  return new Response('{}', {status: next});
};
async function rebootAndCountDown(sequence) {
  answers = sequence; reloads = 0; polls = 0; pollsAtReload = -1; intervals.length = 0;
  await handler();
  assert.strictEqual(intervals.length, 1, 'countdown did not start');
  for (let i = 0; i < 25; i++) await intervals[0]();
}
"""

CHECKS = r"""
(async () => {
  await rebootAndCountDown(['down', 'down', 502, 200]);
  assert.strictEqual(reloads, 1, 'page never reloaded after the portal came back');
  assert.strictEqual(pollsAtReload, 4, 'reloaded before the portal answered 2xx (polls=' + pollsAtReload + ')');

  await rebootAndCountDown(['down', 401]);
  assert.strictEqual(reloads, 1);
  assert.strictEqual(pollsAtReload, 2, 'a 401 after reboot means the portal is up (polls=' + pollsAtReload + ')');

  let fakeNow = 0;
  Date.now = () => (fakeNow += 4000);
  await rebootAndCountDown([]);
  assert.strictEqual(reloads, 0, 'reloaded although the portal never came back');
  assert.strictEqual(btnRebootServer.disabled, false, 'button stays disabled after giving up');
  assert.ok(alerts.some(a => a.includes('仍未检测到服务器恢复')), alerts.join(' | '));
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


def _block(header):
    script = portal.SCRIPT
    if header not in script:
        return ''
    start = script.index(header)
    return script[start:script.index('\n}\n', start) + 3]


@unittest.skipUnless(NODE, 'requires node')
class RebootWaitForPortalTests(unittest.TestCase):
    def test_reload_only_after_the_portal_answers(self):
        source = (HARNESS + _block('async function waitPortalBack(')
                  + _block('if (btnRebootServer) {') + CHECKS)
        r = subprocess.run([NODE, '-e', source], capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
