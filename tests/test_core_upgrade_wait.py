"""核心更新进度：显示任务自己的结果，会话过期时不空等 5 分钟（2026-11-06 修）。

摘出真实的 waitForCoreUpgrade，用 node 驱动。
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
const location = {pathname: '/t/'};
let portalSessionExpired = false;
let clock = 0;
Date.now = () => clock;
globalThis.setTimeout = (fn) => { clock += 2000; fn(); return 0; };
let replies = [];
globalThis.fetch = async () => replies.shift();
"""


@unittest.skipUnless(NODE, 'requires node')
class CoreUpgradeWaitTests(unittest.TestCase):
    def run_js(self, checks):
        s = portal.SCRIPT
        start = s.index('async function waitForCoreUpgrade() {')
        end = s.index('\n}\n', start) + 3
        r = subprocess.run([NODE, '-e', HARNESS + s[start:end] + checks],
                           capture_output=True, text=True, encoding='utf-8', timeout=30)
        return r

    def test_completed_job_message_is_returned(self):
        r = self.run_js(r"""
(async () => {
  replies = [new Response(JSON.stringify({job: {state: 'completed', message: '当前核心版本不低于官方候选，未替换现有补丁'}}))];
  const job = await waitForCoreUpgrade();
  assert(job && job.message.includes('未替换'), '任务结果没有交给调用方');
})().catch(e => { console.error(e); process.exitCode = 1; });
""")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_expired_session_stops_waiting(self):
        r = self.run_js(r"""
(async () => {
  replies = Array.from({length: 200}, () => new Response('x', {status: 401}));
  let err;
  try { await waitForCoreUpgrade(); } catch (e) { err = e; }
  assert(err && err.message.includes('登录已失效'), String(err && err.message));
  assert(replies.length > 190, '会话过期后仍在轮询');
})().catch(e => { console.error(e); process.exitCode = 1; });
""")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
