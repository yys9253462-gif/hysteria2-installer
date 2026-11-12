"""网页切换 AWG 协议线直接以另一条线为目标（2026-11-13 修）。

只有 2 / 3 两条协议线。旧实现先弹原生输入框让管理员手打目标线，打成当前线还要再弹一次「无需切换」；
终端菜单一直是直接切到另一条再确认。在 node 里执行整份页面脚本：点「切换协议线」不弹输入框，
确认框写明从哪条切到哪条，确认后提交的就是另一条线。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick, sandbox, setRespond}) => {
  const prompts = [];
  sandbox.prompt = (message, fallback) => { prompts.push(String(message)); return fallback; };
  sandbox.confirm = () => true;
  setRespond(() => new Response(JSON.stringify({ok: true, message: 'ok'})));
  const before = requests.length;
  els['btn-switch-awg-line'].click();
  await tick();
  const shown = els['custom-confirm-modal'].classList.contains('show');
  const text = String(els['confirm-text'].textContent);
  if (shown) els['confirm-btn-ok'].click();
  await tick();
  const posts = requests.slice(before).filter(r => r.method === 'POST').map(r => String(r.body));
  return {prompts, shown, text, posts};
}
"""


@unittest.skipUnless(NODE, 'requires node')
class AwgSwitchLineDialogTest(unittest.TestCase):
    def test_switches_to_the_other_line_without_a_text_prompt(self):
        report = run_portal_page(page_model(), after=AFTER)
        self.assertEqual(report['errors'], [])
        result = report['after']
        self.assertEqual(result['prompts'], [], '仍然弹出了原生输入框')
        self.assertTrue(result['shown'], '没有弹出页内确认框')
        # 页面初始是 AWG 3.x：确认框要写明从 3.x 切到 2.x，并保留「配置会失效」的警告。
        self.assertIn('AWG 3.x', result['text'])
        self.assertIn('AWG 2.x', result['text'])
        self.assertIn('失效', result['text'])
        self.assertEqual(len(result['posts']), 1, result['posts'])
        self.assertIn('action=set_line', result['posts'][0])
        self.assertIn('line=2', result['posts'][0])


if __name__ == '__main__':
    unittest.main()
