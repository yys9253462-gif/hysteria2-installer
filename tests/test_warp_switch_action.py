"""WARP 开关等状态查到才显示，并按状态发送明确的开启 / 关闭（2026-11-13 修）。

旧页面一加载就显示「切换中...」的开关且可点，状态查询失败时它一直停在那里；点下去发 action=toggle，
由服务端翻转 —— 管理员不知道当前是开是关，结果全凭运气。
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, render, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick, sandbox, setRespond}) => {
  const btn = els['btn-toggle-warp'];
  let cls = '';
  Object.defineProperty(btn, 'className', {configurable: true, get: () => cls, set: v => { cls = String(v); }});
  btn.classList.contains = c => cls.split(/\s+/).includes(c);
  let enabled = true;
  setRespond(url => new Response(JSON.stringify(url.endsWith('warp-status')
    ? {ok: true, installed: true, enabled, connected: true, applied: true, rules: []}
    : {ok: true})));
  const sent = [];
  for (const state of [true, false]) {
    enabled = state;
    await sandbox.checkWarpStatus();
    const before = requests.length;
    btn.click();
    await tick();
    sent.push(requests.slice(before).filter(r => r.method === 'POST').map(r => String(r.body)));
  }
  return {sent};
}
"""


class WarpSwitchActionTest(unittest.TestCase):
    def test_switch_is_hidden_until_the_status_is_known(self):
        tag = re.search(r'<button\b[^>]*\bid="btn-toggle-warp"[^>]*>', render()).group(0)
        self.assertIn('display:none', tag)

    @unittest.skipUnless(NODE, 'requires node')
    def test_switch_sends_the_explicit_action_for_the_shown_state(self):
        report = run_portal_page(page_model(), after=AFTER)
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['after']['sent'], [['action=disable'], ['action=enable']])


if __name__ == '__main__':
    unittest.main()
