"""面板自更新后等门户真正恢复再刷新（2026-11-12 修）。

面板更新会重启门户；新版本起不来时重启脚本 20 秒后自动回滚再重启。旧实现固定 5 秒后
location.reload()，重启稍慢或走了回滚就落到浏览器的「无法访问此网站」。核心 / AWG 更新
不重启门户，仍按 5 秒刷新。摘出真实的 doUpgrade，用 node 驱动。
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
const events = [];
const location = {pathname: '/t/', reload() { events.push('reload'); }};
globalThis.setTimeout = (fn, ms) => { events.push('timer:' + ms); fn(); return 0; };
globalThis.confirm = () => true;
globalThis.alert = msg => events.push('alert:' + msg);
const updateStatusMsg = {textContent: ''};
const coreVerDisplay = {textContent: '2.6.5（最新）'};
const btnUpdateCore = {disabled: false, textContent: ''};
const btnUpdatePortal = {disabled: false, textContent: ''};
const btnUpdateAwgEngine = null;
let portalBack = true;
async function waitPortalBack() { events.push('wait'); return portalBack; }
async function waitForCoreUpgrade() { return {}; }
globalThis.fetch = async () => new Response(JSON.stringify({ok: true, message: '已更新'}));
"""

CHECKS = r"""
(async () => {
  await doUpgrade('portal');
  assert.ok(events.includes('wait'), 'portal update reloaded without waiting for the portal: ' + events);
  assert.ok(events.indexOf('wait') < events.indexOf('reload'), events.join(','));
  events.length = 0;
  portalBack = false;
  await doUpgrade('portal');
  assert.ok(!events.includes('reload'), 'reloaded although the portal never came back');
  assert.ok(updateStatusMsg.textContent.includes('手动刷新'), updateStatusMsg.textContent);
  events.length = 0;
  await doUpgrade('core');
  assert.ok(!events.includes('wait'), 'a core update does not restart the portal');
  assert.ok(events.includes('timer:5000') && events.includes('reload'), events.join(','));
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


@unittest.skipUnless(NODE, 'requires node')
class PortalUpdateWaitTests(unittest.TestCase):
    def test_portal_update_reloads_only_after_the_portal_answers_again(self):
        s = portal.SCRIPT
        start = s.index('async function doUpgrade(target) {')
        block = s[start:s.index('\n}\n', start) + 3]
        r = subprocess.run([NODE, '-e', HARNESS + block + CHECKS],
                           capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
