"""出站探测：选了 SOCKS5 / HTTP 却没填代理地址时直接提示，不发请求（2026-11-13 修）。

旧实现照样把空地址发给服务器，换回一行英文报错显示在探测结果下面。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick, setRespond}) => {
  setRespond(() => new Response(JSON.stringify({ok: true, ip: '198.51.100.7', kind: 'socks5'})));
  const probes = since => requests.slice(since).filter(r => r.url.endsWith('outbounds/probe')).length;
  els['ob-probe-kind'].value = 'socks5';
  els['ob-probe-addr'].value = '';
  let before = requests.length;
  els['btn-ob-probe'].click();
  await tick();
  const out = {emptySent: probes(before), emptyNote: String(els['ob-outbound-ip-note'].textContent)};
  els['ob-probe-addr'].value = '1.2.3.4:1080';
  before = requests.length;
  els['btn-ob-probe'].click();
  await tick();
  out.filledSent = probes(before);
  out.filledIp = String(els['ob-outbound-ip'].textContent);
  return out;
}
"""


@unittest.skipUnless(NODE, 'requires node')
class OutboundProbeFeedbackTest(unittest.TestCase):
    def test_missing_proxy_address_is_caught_before_sending(self):
        report = run_portal_page(page_model(), after=AFTER)
        self.assertEqual(report['errors'], [])
        r = report['after']
        self.assertEqual(r['emptySent'], 0, '没填代理地址也发出了探测请求')
        self.assertIn('代理地址', r['emptyNote'])
        self.assertEqual(r['filledSent'], 1)
        self.assertEqual(r['filledIp'], '198.51.100.7')


if __name__ == '__main__':
    unittest.main()
