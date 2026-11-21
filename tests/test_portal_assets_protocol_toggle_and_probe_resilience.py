"""回归测试：门户五大协议开关失败恢复按钮文案、空配置渲染防护及非 JSON 错误页处理。"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

ASSETS = (ROOT / 'portal_assets.py').read_text(encoding='utf-8').replace('\r\n', '\n')

NODE_VERIFY = r"""
async ({els, tick, sandbox, setRespond}) => {
  const alerts = [];
  sandbox.alert = msg => alerts.push(String(msg));

  // 1) checkVmessStatus / checkVlessencStatus 在 active=true 且 config=null 时不得崩溃
  setRespond(url => {
    if (url.endsWith('vmess-status') || url.endsWith('vlessenc-status')) {
      return new Response(JSON.stringify({ok: true, installed: true, active: true, config: null}));
    }
    return new Response(JSON.stringify({ok: true}));
  });
  await sandbox.checkVmessStatus();
  await sandbox.checkVlessencStatus();
  const vmessNullText = els['vmess-badge'].textContent;
  const vlessNullText = els['vlessenc-badge'].textContent;

  // 2) 五大协议开关在 manage-* 网络异常（reject）时，按钮文案必须恢复，不得卡在「切换中...」
  const protos = ['reality', 'vmess', 'vlessenc', 'anytls', 'tuic'];
  const afterReject = {};
  setRespond(url => {
    if (url.includes('manage-')) {
      return Promise.reject(new Error('network down'));
    }
    return new Response(JSON.stringify({ok: true, installed: true, active: false, enabled: false, config: {port: 2443}}));
  });
  for (const name of protos) {
    const btn = els['btn-toggle-' + name];
    let cls = 'toggle-btn off';
    Object.defineProperty(btn, 'className', {configurable: true, get: () => cls, set: v => { cls = String(v); }});
    btn.classList.contains = c => cls.split(/\s+/).includes(c);
    btn.textContent = '已关闭 (点击开启)';
    btn.disabled = false;
    btn.click();
    await tick();
    afterReject[name] = {text: btn.textContent, disabled: btn.disabled};
  }

  // 3) obTestForm 遇到反代 502 HTML 错误页时，不得把 SyntaxError 当提示，应含 HTTP 502
  setRespond(url => {
    if (url.endsWith('outbounds/probe')) {
      return new Response('<html>502 Bad Gateway</html>', {status: 502});
    }
    return new Response(JSON.stringify({ok: true}));
  });
  els['ob-type'].value = 'socks5';
  els['ob-socks-addr'].value = '1.2.3.4:1080';
  els['ob-socks-user'].value = '';
  els['ob-socks-pass'].value = '';
  await sandbox.obTestForm();
  const probe502Msg = els['ob-form-msg'].textContent;

  return {vmessNullText, vlessNullText, afterReject, probe502Msg, alerts};
}
"""


class PortalAssetsProtocolToggleAndProbeResilienceTests(unittest.TestCase):
    def test_source_guards_for_protocol_toggles_and_null_config(self):
        """源码层面核对非 JSON 响应兜底、空 config 判空与按钮文案回退。"""
        # checkVmessStatus / checkVlessencStatus 不得在 const cfg = json.config || {} 之前裸读 json.config.port
        self.assertNotIn('json.config.port', ASSETS)
        # btnToggleReality 必须具备防双击与非 JSON 响应兜底
        m = re.search(r"if \(btnToggleReality\) \{[\s\S]*?\n\}", ASSETS)
        self.assertIsNotNone(m)
        block = m.group(0)
        self.assertIn('if (btnToggleReality.disabled) return;', block)
        self.assertIn("切换失败（HTTP ' + res.status", block)
        # 五大开关全部记录 prevText 并在 finally 避免残留「切换中...」
        for btn in ('btnToggleReality', 'btnToggleVmess', 'btnToggleVlessenc', 'btnToggleAnytls', 'btnToggleTuic'):
            bm = re.search(rf"if \({btn}\) \{{[\s\S]*?\n\}}", ASSETS)
            self.assertIsNotNone(bm, f'未找到 {btn} 事件块')
            self.assertIn("=== '切换中...'", bm.group(0), f'{btn} 失败时未恢复切换中文案')

    @unittest.skipUnless(NODE, 'requires node')
    def test_runtime_behavior_in_node_sandbox(self):
        report = run_portal_page(page_model(), after=NODE_VERIFY)
        self.assertEqual(report['errors'], [])
        res = report['after']
        self.assertIn('运行中', res['vmessNullText'])
        self.assertIn('运行中', res['vlessNullText'])
        for name, state in res['afterReject'].items():
            with self.subTest(protocol=name):
                self.assertEqual(state['text'], '已关闭 (点击开启)')
                self.assertFalse(state['disabled'])
        self.assertIn('502', res['probe502Msg'])
        self.assertNotIn('Unexpected token', res['probe502Msg'])


if __name__ == '__main__':
    unittest.main()
