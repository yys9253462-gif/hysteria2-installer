"""后台轮询只在对应页面可见时进行（2026-11-12 修）。

旧实现不论停在哪一页：网速每 2 秒请求 /traffic-speed（服务端在 data_lock 内给每个用户
算用量摘要，会拖慢 Hy2 鉴权），WARP 状态每 10 秒请求 /warp-status（每次 systemctl show、
把出站配置重渲染一遍比对，30 秒一次还经 WARP 探测出口）。按真实页面执行整份
portal.SCRIPT，在不同页面上触发全部定时器，看哪些接口被请求；切进页面时要立刻刷新一次。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ctx => {
  const out = {periods: ctx.intervals.map(it => it.ms).sort((a, b) => a - b)};
  const take = () => ctx.requests.splice(0).map(r => r.url.replace('/t/', ''));
  for (const hash of ['#connect', '#cores', '#users', '#proxies/warp', '#proxies/awg']) {
    take();
    await ctx.go(hash);
    const entered = take();
    for (const it of ctx.intervals) it.fn();
    await ctx.tick();
    out[hash] = {entered, polled: take(), tab: ctx.state().tab};
  }
  const click = async btn => { take(); btn.click(); await ctx.tick(); return take(); };
  await ctx.go('#connect');
  out.clickUsers = await click(ctx.tabBtns.find(b => b.dataset.tab === 'users'));
  await click(ctx.tabBtns.find(b => b.dataset.tab === 'proxies'));
  out.clickWarp = await click(ctx.subBtns.find(b => b.dataset.subtab === 'warp'));
  return out;
}
"""


@unittest.skipUnless(NODE, 'requires node')
class BackgroundPollingTests(unittest.TestCase):
    def test_polls_only_run_for_the_visible_panel_and_refresh_on_entry(self):
        report = run_portal_page(page_model(), '', after=AFTER)
        self.assertEqual(report['errors'], [])
        after = report['after']
        self.assertIn(2000, after['periods'])
        self.assertIn(10000, after['periods'])
        expected = {'#connect': set(), '#cores': set(), '#proxies/awg': set(),
                    '#users': {'traffic-speed'}, '#proxies/warp': {'warp-status'}}
        for hash, wanted in expected.items():
            with self.subTest(hash=hash):
                polled = set(after[hash]['polled']) & {'traffic-speed', 'warp-status'}
                self.assertEqual(polled, wanted, after[hash])
                self.assertTrue(wanted <= set(after[hash]['entered']),
                                'entering %s did not refresh it: %s' % (hash, after[hash]))
        self.assertIn('traffic-speed', after['clickUsers'], 'clicking the users tab did not refresh it')
        self.assertIn('warp-status', after['clickWarp'], 'clicking the WARP sub-tab did not refresh it')


if __name__ == '__main__':
    unittest.main()
