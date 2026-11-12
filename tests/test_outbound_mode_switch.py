"""出站模式切换：全局先确认、请求期间不接受第二次点击、点当前模式不发请求（2026-11-13 修）。

每次切换都要重启服务。旧实现点一下就发：连点两下重启两次，点当前模式也重启一次；全局模式下所有网站
都走列表里的第一个出站，它不通时所有人断网，页面自己都建议先用「按域名分流」，切过去却没有任何确认。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick, sandbox, setRespond}) => {
  let release = null;
  setRespond(url => url.endsWith('manage-outbounds')
    ? new Promise(done => { release = () => done(new Response(JSON.stringify({ok: true, mode: 'global'}))); })
    : new Response(JSON.stringify({ok: true, mode: 'global', outbounds: [], rules: [], builtin: []})));
  sandbox.obSetModeUI('rules');
  const globalBtn = els['btn-ob-mode-global'], rulesBtn = els['btn-ob-mode-rules'];
  const modal = els['custom-confirm-modal'];
  const posts = since => requests.slice(since).filter(q => q.method === 'POST').map(q => String(q.body));
  const out = {};
  let before = requests.length;
  rulesBtn.click(); await tick();
  out.activeClick = posts(before);
  before = requests.length;
  globalBtn.click(); await tick();
  out.asked = modal.classList.contains('show');
  out.danger = String(els['confirm-btn-ok'].className).includes('danger');
  els['confirm-btn-cancel'].click(); await tick();
  out.afterCancel = posts(before);
  before = requests.length;
  globalBtn.click(); await tick();
  els['confirm-btn-ok'].click(); await tick();
  out.busy = [globalBtn.disabled, rulesBtn.disabled];
  rulesBtn.click(); globalBtn.click(); await tick();
  out.inFlight = posts(before);
  if (release) release();
  await tick(); await tick();
  out.after = [globalBtn.disabled, rulesBtn.disabled];
  return out;
}
"""


@unittest.skipUnless(NODE, 'requires node')
class OutboundModeSwitchTest(unittest.TestCase):
    def test_mode_switch_is_confirmed_and_not_repeated(self):
        report = run_portal_page(page_model(), after=AFTER)
        self.assertEqual(report['errors'], [])
        r = report['after']
        self.assertEqual(r['activeClick'], [], '点当前模式也发了切换请求（会重启服务）')
        self.assertTrue(r['asked'], '切到全局前没有确认')
        self.assertTrue(r['danger'])
        self.assertEqual(r['afterCancel'], [], '点了「取消」仍发出了请求')
        self.assertEqual(r['busy'], [True, True], '切换期间模式按钮仍可点')
        self.assertEqual(r['inFlight'], ['action=mode&mode=global'], '切换期间再点又发了请求')
        self.assertEqual(r['after'], [False, False], '切换结束后按钮没有恢复')


if __name__ == '__main__':
    unittest.main()
