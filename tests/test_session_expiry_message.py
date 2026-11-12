"""登录过期时，页面上的报错一律是中文说明（2026-11-13 修）。

页面请求只靠 Cookie 鉴权，401 只能是登录过期。多数端点的 401 回 JSON {"ok":false,"error":"Unauthorized"}；
SCRIPT 开头的 Response.json 包装只在解析失败时才换成中文，解析得出来就把这个英文单词原样交给各个按钮弹出来。
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_hash_routing import page_model, run_portal_page  # noqa: E402

NODE = shutil.which('node')
EXPIRED = '登录已过期，请刷新页面重新登录'

CHECKS = r"""
const assert = require('assert');
(async () => {
  const cases = [
    [new Response(JSON.stringify({ok: false, error: 'Unauthorized'}), {status: 401}), EXPIRED],
    [new Response('Authentication required', {status: 401}), EXPIRED],
    [new Response('slow down', {status: 429}), '请求太频繁，请稍后再试'],
    [new Response(JSON.stringify({ok: false, error: '具体原因'}), {status: 409}), '具体原因'],
  ];
  for (const [res, want] of cases) {
    const json = await res.json();
    assert.strictEqual(json.ok, false);
    assert.strictEqual(json.error, want);
  }
  assert.deepStrictEqual(await new Response(JSON.stringify({ok: true, n: 1})).json(), {ok: true, n: 1});
})().catch(e => { console.error(e); process.exitCode = 1; });
"""

AFTER = r"""
async ({els, alerts, tick, setRespond}) => {
  setRespond(() => new Response(JSON.stringify({ok: false, error: 'Unauthorized'}), {status: 401}));
  els['btn-update-awg'].click();
  await tick();
  if (els['custom-confirm-modal'].classList.contains('show')) els['confirm-btn-ok'].click();
  await tick(); await tick();
  return {alerts: alerts.slice()};
}
"""


@unittest.skipUnless(NODE, 'requires node')
class SessionExpiryMessageTest(unittest.TestCase):
    def test_json_wrapper_explains_an_expired_session(self):
        script = portal.SCRIPT
        prelude = script[:script.index('// 会话过期后停掉后台轮询')]
        js = 'const EXPIRED = %r;\n' % EXPIRED + prelude + CHECKS
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_buttons_show_the_explanation_not_the_raw_word(self):
        report = run_portal_page(page_model(), after=AFTER)
        self.assertEqual(report['errors'], [])
        alerts = report['after']['alerts']
        self.assertIn(EXPIRED, alerts)
        self.assertFalse([a for a in alerts if 'Unauthorized' in a], alerts)


if __name__ == '__main__':
    unittest.main()
