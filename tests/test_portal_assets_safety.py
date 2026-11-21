"""回归测试：门户前端 Response.json 非对象防护、代理复制链接去重转义与弹窗字段转义。"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')
NODE = shutil.which('node')


class PortalAssetsSafetyTests(unittest.TestCase):
    @unittest.skipUnless(NODE, 'requires node')
    def test_response_json_wrapper_handles_null_and_primitive_payloads(self):
        m = re.search(r'(\(function \(\) \{\n  const parseJson = Response\.prototype\.json;.*?\n\}\)\(\);)', ASSETS, re.S)
        self.assertIsNotNone(m, '未找到 Response.prototype.json 拦截器')
        js = m.group(1) + r"""
(async () => {
  for (const body of ['null', '123', '"oops"', 'false']) {
    const r = new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } });
    const parsed = await r.json();
    if (!parsed || typeof parsed !== 'object' || parsed.ok !== false || !parsed.error) {
      console.error('BAD_RESULT', body, parsed);
      process.exit(1);
    }
  }
  const okResp = new Response('{"ok":true,"n":1}', { status: 200 });
  const okData = await okResp.json();
  if (!okData || okData.ok !== true || okData.n !== 1) {
    console.error('BROKE_VALID_OBJECT', okData);
    process.exit(2);
  }
  console.log('PASS');
})();
"""
        res = subprocess.run([NODE, '-e', js], capture_output=True, text=True, timeout=15)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn('PASS', res.stdout)

    def test_proxy_copy_link_does_not_double_escape_full_url(self):
        self.assertNotIn(
            'const fullUrl = `${obEsc(s.type)}://${encodeURIComponent(s.username)}:${encodeURIComponent(s.password)}@${obEsc(curProxyServerHost)}:${obEsc(s.port)}`;',
            ASSETS,
            'fullUrl 先 obEsc 又在 data-copy-link 里二次 obEsc，导致双重转义',
        )

    def test_user_modal_meta_bar_escapes_dynamic_text(self):
        self.assertIn('<span>📅 到期: <b>${obEsc(expireText)}</b></span>', ASSETS)
        self.assertIn('<span>📊 流量: <b>${obEsc(trafficText)}</b></span>', ASSETS)
        self.assertIn('<span>📱 IP限制: <b>${obEsc(ipText)}</b></span>', ASSETS)


if __name__ == '__main__':
    unittest.main()
