"""二次确认一律用页内确认框（2026-11-13 修）。

原生 confirm() 的默认按钮是「确定」，回车即执行：切换 AWG 协议线（已发放的配置全部失效）、
重新生成 Reality 密钥、删除客户端 / 出站 / 代理这类操作一碰就生效，样式也和页面其它确认不一致。
升级核心那条的换行还写成了 \\n，弹窗上显示出字面的「\n」。
在 node 里执行整份页面脚本，逐个触发这些操作：不许调用原生 confirm，页内确认框要弹出，
破坏性操作用危险样式，点「取消」后不发任何 POST。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ({els, requests, tick, sandbox, setRespond}) => {
  const native = [];
  sandbox.confirm = m => { native.push(String(m)); return false; };
  sandbox.prompt = () => '2';
  const missing = [];
  const need = id => els[id] || (missing.push(id), null);
  const modal = need('custom-confirm-modal'), ok = need('confirm-btn-ok');
  const cancel = need('confirm-btn-cancel'), text = need('confirm-text');
  const fakeButton = (attr, value) => {
    const listeners = {};
    return {disabled: false, dataset: {proxyDel: value}, getAttribute: n => (n === attr ? value : null),
            closest: () => null, addEventListener(t, f) { (listeners[t] = listeners[t] || []).push(f); },
            fire() { for (const f of listeners.click || []) f({type: 'click', preventDefault() {}}); }};
  };
  const awgDel = fakeButton('data-awg-del', 'phone');
  const proxyDel = fakeButton('data-proxy-del', 'p1');
  const awgTbody = need('awg-peer-tbody'), proxyTbody = need('proxy-tbody');
  for (const id of ['awg-endpoint-input', 'awg-line-select', 'core-ver-display', 'ob-list', 'btn-reset-reality-keys',
                    'btn-switch-awg-line', 'btn-update-awg', 'btn-do-install-awg', 'btn-install-warp',
                    'btn-reset-warp-rules', 'btn-install-gost']) need(id);
  if (missing.length) return {missing};

  awgTbody.querySelectorAll = sel => (sel === '[data-awg-del]' ? [awgDel] : []);
  sandbox.renderAwgPeers([{name: 'phone', address: '10.8.0.2/32'}]);
  proxyTbody.querySelectorAll = sel => (sel === '[data-proxy-del]' ? [proxyDel] : []);
  setRespond(url => new Response(JSON.stringify(url.endsWith('proxy-services')
    ? {ok: true, gost_installed: true, gost_active: true,
       services: [{id: 'p1', type: 'socks5', username: 'u', password: 'p', port: 1080}]}
    : {ok: false, error: 'stub'})));
  await sandbox.loadProxyServices();
  els['awg-endpoint-input'].value = 'vpn.example.com';
  els['awg-line-select'].value = '3';
  els['core-ver-display'].textContent = 'v2.6.5+patch';
  const obDel = {getAttribute: n => (n === 'data-ob-del' ? 'proxy-a' : null)};

  const actions = {
    reality_reset: () => els['btn-reset-reality-keys'].click(),
    awg_switch_line: () => els['btn-switch-awg-line'].click(),
    awg_update: () => els['btn-update-awg'].click(),
    awg_install: () => els['btn-do-install-awg'].click(),
    awg_peer_delete: () => awgDel.fire(),
    proxy_delete: () => proxyDel.fire(),
    gost_install: () => els['btn-install-gost'].click(),
    warp_install: () => els['btn-install-warp'].click(),
    warp_reset_rules: () => els['btn-reset-warp-rules'].click(),
    warp_rule_delete: () => { sandbox.delWarpRule('example.com'); },
    outbound_delete: () => els['ob-list'].dispatch('click', {
      type: 'click', preventDefault() {}, target: {closest: sel => (sel === '[data-ob-del]' ? obDel : null)}}),
    core_upgrade_custom: () => { sandbox.doUpgrade('core'); },
  };
  const results = {};
  for (const [name, fire] of Object.entries(actions)) {
    native.length = 0;
    const before = requests.length;
    fire();
    await tick();
    const shown = modal.classList.contains('show');
    results[name] = {native: native.slice(), shown, danger: String(ok.className).includes('danger'),
                     text: String(text.textContent)};
    if (shown) cancel.click();
    await tick();
    results[name].posted = requests.slice(before).filter(r => r.method === 'POST').map(r => r.url);
  }
  return {results};
}
"""

DESTRUCTIVE = ('reality_reset', 'awg_switch_line', 'awg_peer_delete', 'proxy_delete', 'warp_reset_rules',
               'warp_rule_delete', 'outbound_delete', 'core_upgrade_custom')


@unittest.skipUnless(NODE, 'requires node')
class PageConfirmDialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_portal_page(page_model(), after=AFTER)
        cls.results = cls.report['after'].get('results', {})

    def test_harness_found_every_control(self):
        self.assertEqual(self.report['after'].get('missing', []), [])
        self.assertEqual(self.report['errors'], [])
        self.assertEqual(len(self.results), 12)

    def test_confirmations_use_the_page_dialog_and_cancel_sends_nothing(self):
        for name, r in self.results.items():
            with self.subTest(action=name):
                self.assertEqual(r['native'], [], '调用了原生 confirm')
                self.assertTrue(r['shown'], '页内确认框没有弹出')
                self.assertEqual(r['posted'], [], '点了「取消」仍发出了请求')

    def test_destructive_actions_use_the_danger_style(self):
        for name in DESTRUCTIVE:
            with self.subTest(action=name):
                self.assertTrue(self.results[name]['danger'], '危险操作没有用危险样式（焦点会停在「确定」）')
        self.assertFalse(self.results['gost_install']['danger'])

    def test_upgrade_notice_keeps_its_line_break(self):
        text = self.results['core_upgrade_custom']['text']
        self.assertIn('\n当前含定制补丁', text)
        self.assertNotIn('\\n', text)


if __name__ == '__main__':
    unittest.main()
