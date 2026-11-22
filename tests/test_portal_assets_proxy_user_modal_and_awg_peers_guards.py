"""回归测试：前端入站代理列表脏项/原型键/SVG净化、用户弹窗 SVG 净化与 AWG 脏 peer 过滤及防双击。"""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

NODE = shutil.which('node')


class PortalAssetsProxyUserModalAndAwgPeersGuardsTests(unittest.TestCase):
    def _run_node(self, js_code):
        if not NODE:
            self.skipTest('requires node')
        res = subprocess.run(
            [NODE, '-e', js_code],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=15,
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_load_proxy_services_filters_null_items_and_blocks_prototype_type(self):
        """loadProxyServices 遇到 null/非对象条目不得崩溃，且 type='constructor' 不得命中 Object 原型。"""
        script = portal.SCRIPT
        ob_esc_s = script.index('function obEsc(')
        ob_esc_e = script.index('\nfunction ', ob_esc_s + 1)
        fn_s = script.index('async function loadProxyServices()')
        fn_e = script.index('// proxyForm replaced', fn_s)
        snippet = script[ob_esc_s:ob_esc_e] + '\n' + script[fn_s:fn_e]
        js = r"""
const assert = require('assert');
let renderedHtml = '';
const proxyTbody = {
  set innerHTML(v) { renderedHtml = v; },
  get innerHTML() { return renderedHtml; },
  querySelectorAll: () => [],
};
const gostBadge = { textContent: '', style: {} };
const btnInstallGost = { style: {}, textContent: '' };
let curProxyServerHost = '1.2.3.4';
const location = { pathname: '/' };
const markStatusUnknown = () => { throw new Error('不应触发异常降级'); };
const markLoadFailed = (_el, msg) => { throw new Error('不应加载失败: ' + msg); };
globalThis.fetch = async () => ({
  ok: true,
  status: 200,
  json: async () => ({
    ok: true,
    gost_installed: true,
    gost_active: true,
    host: '2001:db8::1',
    services: [
      null,
      123,
      { id: 'p1', type: 'constructor', port: 1080, username: 'u', password: 'p' },
      { id: 'p2', type: 'socks5', port: 1081, username: 'u2', password: 'p2' },
    ],
  }),
});
""" + snippet + r"""
(async () => {
  await loadProxyServices();
  assert(renderedHtml.includes('1081'), '合法代理行必须正常渲染');
  assert(!renderedHtml.includes('function Object'), 'type=constructor 不得命中 Object 原型属性');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

    def test_show_proxy_result_blocks_script_svg_and_sanitizes_type_class(self):
        """showProxyResult 必须拦截含 <script 的二维码 SVG 并按白名单清洗 proxy-type 类名。"""
        script = portal.SCRIPT
        fn_s = script.index('function showProxyResult(')
        fn_e = script.index('// 绑定秒级一键生成按钮', fn_s)
        snippet = script[fn_s:fn_e]
        js = r"""
const assert = require('assert');
const proxyModal = { classList: { add() {} } };
const resPTypeBadge = { textContent: '', className: '' };
const resPHost = { textContent: '' };
const resPPort = { textContent: '' };
const resPUser = { textContent: '' };
const resPPass = { textContent: '' };
const resPUrl = { value: '' };
const resPFmt = { value: '' };
const resPQr = { innerHTML: '' };
const btnCopyPUrl = {};
const btnCopyPFmt = {};
const pmClose = {};
const curProxyServerHost = '1.2.3.4';
const focusModal = () => {};
globalThis.document = { querySelectorAll: () => [] };
""" + snippet + r"""
showProxyResult({
  host: '1.2.3.4',
  port: 1080,
  type: 'socks5 evil-cls',
  username: 'u',
  password: 'p',
  qr: '<svg><script>alert(1)</script></svg>',
});
assert(!resPQr.innerHTML.includes('<script'), 'showProxyResult 不得把含 <script 的 SVG 写入 innerHTML');
assert.strictEqual(resPTypeBadge.className, 'proxy-type', '非法 type 不得拼入 className');
"""
        self._run_node(js)

    def test_render_awg_peers_filters_missing_name_and_guards_double_click(self):
        """renderAwgPeers 必须过滤缺少字符串 name 的脏条目，且删除按钮与代理删除按钮均须防双击。"""
        script = portal.SCRIPT
        ob_esc_s = script.index('function obEsc(')
        ob_esc_e = script.index('\nfunction ', ob_esc_s + 1)
        fmt_s = script.index('function fmtAwgCreated(')
        fn_e = script.index('if (btnInstallAwg)', fmt_s)
        snippet = script[ob_esc_s:ob_esc_e] + '\n' + script[fmt_s:fn_e]
        js = r"""
const assert = require('assert');
let html = '';
const awgPeerTbody = {
  set innerHTML(v) { html = v; },
  get innerHTML() { return html; },
  querySelectorAll: () => [],
};
""" + snippet + r"""
renderAwgPeers([
  null,
  {},
  { name: null, address: '10.66.66.2' },
  { name: 'alice', address: '10.66.66.3', created_at: '' },
]);
assert(html.includes('alice'), '合法 peer 应渲染');
assert(!html.includes('data-awg-del="undefined"'), '缺 name 的脏 peer 不得渲染为 undefined 按钮');
assert(!html.includes('data-awg-del="null"'), 'name=null 的脏 peer 不得渲染为 null 按钮');
"""
        self._run_node(js)

        # 源码级检查：用户弹窗 SVG 拦截 <script、代理删除与 AWG 删除防双击
        modal_blk = script[script.index("document.querySelectorAll('.btn-user-connect')"):script.index('/* ==================== AmneziaWG')]
        self.assertIn('!/<script/i.test(json.qr_svg)', modal_blk)
        proxy_del_blk = script[script.index("proxyTbody.querySelectorAll('[data-proxy-del]')"):script.index('// proxyForm replaced')]
        self.assertIn('if (btn.disabled) return;', proxy_del_blk)
        awg_del_s = script.index("awgPeerTbody.querySelectorAll('[data-awg-del]')")
        awg_del_blk = script[awg_del_s:script.index('if (btnInstallAwg)', awg_del_s)]
        self.assertIn('if (b.disabled) return;', awg_del_blk)


if __name__ == '__main__':
    unittest.main()
