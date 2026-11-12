"""协议开关按卡片显示的状态发送明确的开启 / 关闭，关闭前先确认（2026-11-13 修）。

旧实现一律发 action=toggle、由服务端翻转：页面停留久了或在别处改过时，卡片写着「已关闭（点击开启）」，
点下去却把协议关掉；关闭也没有任何确认，手滑一下这个协议上的用户全部断开。控制台一直是
enable / disable，停用要危险确认。在 node 里执行整份页面脚本，逐个点 5 个协议的开关。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick, sandbox, setRespond}) => {
  const PROTOCOLS = {
    reality: {check: 'checkRealityStatus', on: true},
    vmess: {check: 'checkVmessStatus', on: false},
    vlessenc: {check: 'checkVlessencStatus', on: true},
    anytls: {check: 'checkAnytlsStatus', on: true},
    tuic: {check: 'checkTuicStatus', on: false},
  };
  setRespond(url => {
    for (const [name, p] of Object.entries(PROTOCOLS)) {
      if (url.endsWith(name + '-status')) return new Response(JSON.stringify(
        {ok: true, installed: true, active: p.on, enabled: p.on, config: {port: 2443, uri: 'x://y'}}));
    }
    return new Response(JSON.stringify({ok: true}));
  });
  const modal = els['custom-confirm-modal'], ok = els['confirm-btn-ok'], cancel = els['confirm-btn-cancel'];
  const posts = (since, path) => requests.slice(since)
    .filter(q => q.method === 'POST' && (!path || q.url.endsWith(path))).map(q => String(q.body));
  const results = {};
  for (const [name, p] of Object.entries(PROTOCOLS)) {
    const btn = els['btn-toggle-' + name];
    // 真实浏览器里 className 与 classList 同步；假 DOM 里两者各管各的，这里补上同步。
    let cls = '';
    Object.defineProperty(btn, 'className', {configurable: true, get: () => cls, set: v => { cls = String(v); }});
    btn.classList.contains = c => cls.split(/\s+/).includes(c);
    await sandbox[p.check]();
    const r = {state: cls};
    const before = requests.length;
    btn.click(); await tick();
    r.asked = modal.classList.contains('show');
    r.danger = String(ok.className).includes('danger');
    if (r.asked) {
      cancel.click(); await tick();
      r.afterCancel = posts(before);
      btn.click(); await tick();
      ok.click(); await tick();
    }
    r.sent = posts(before, 'manage-' + name);
    results[name] = r;
  }
  return results;
}
"""


@unittest.skipUnless(NODE, 'requires node')
class ProtocolSwitchActionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_portal_page(page_model(), after=AFTER)
        cls.results = cls.report['after']

    def test_harness_reached_every_switch(self):
        self.assertEqual(self.report['errors'], [])
        self.assertEqual({name: r['state'] for name, r in self.results.items()},
                         {'reality': 'toggle-btn on', 'vmess': 'toggle-btn off', 'vlessenc': 'toggle-btn on',
                          'anytls': 'toggle-btn on', 'tuic': 'toggle-btn off'})

    def test_switching_off_asks_first_and_sends_disable(self):
        for name in ('reality', 'vlessenc', 'anytls'):
            with self.subTest(protocol=name):
                r = self.results[name]
                self.assertTrue(r['asked'], '关闭前没有确认')
                self.assertTrue(r['danger'], '关闭确认没有用危险样式')
                self.assertEqual(r['afterCancel'], [], '点了「取消」仍发出了请求')
                self.assertEqual(r['sent'], ['action=disable'])

    def test_switching_on_sends_enable_without_asking(self):
        for name in ('vmess', 'tuic'):
            with self.subTest(protocol=name):
                r = self.results[name]
                self.assertFalse(r['asked'])
                self.assertEqual(r['sent'], ['action=enable'])


if __name__ == '__main__':
    unittest.main()
