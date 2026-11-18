"""「安全重启服务器」按危险操作确认（2026-11-13 修）。

重启期间所有用户的连接都会中断。旧实现用警告样式，焦点停在「确定」，回车就重启，提示里也没说会断开。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick}) => {
  const before = requests.length;
  els['btn-reboot-server'].click();
  await tick();
  const out = {asked: els['custom-confirm-modal'].classList.contains('show'),
               danger: String(els['confirm-btn-ok'].className).includes('danger'),
               text: String(els['confirm-text'].textContent)};
  els['confirm-btn-cancel'].click();
  await tick();
  out.posts = requests.slice(before).filter(r => r.method === 'POST').map(r => r.url);
  return out;
}
"""


@unittest.skipUnless(NODE, 'requires node')
class RebootConfirmDangerTest(unittest.TestCase):
    def test_reboot_is_confirmed_as_a_dangerous_action(self):
        report = run_portal_page(page_model(), after=AFTER)
        self.assertEqual(report['errors'], [])
        r = report['after']
        self.assertTrue(r['asked'])
        self.assertTrue(r['danger'], '重启服务器的确认没有用危险样式（焦点会停在「确定」）')
        self.assertIn('中断', r['text'])
        self.assertEqual(r['posts'], [])


if __name__ == '__main__':
    unittest.main()
