"""回归测试：门户前端出站 IPv6/端口解析、探测竞态序号、协议二维码 SVG 净化、表单与规则防双击及会话过期早停。"""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

NODE = shutil.which('node')


@unittest.skipUnless(NODE, 'requires node')
class PortalAssetsOutboundQrAndFormGuardsTests(unittest.TestCase):
    def _run_node(self, code):
        proc = subprocess.run(
            [NODE, '-e', code],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_ob_parse_link_supports_ipv6_and_rejects_out_of_range_ports(self):
        """obParseLink 必须支持 IPv6 字面量地址并拒绝 0/超 65535 端口。"""
        script = portal.SCRIPT
        start = script.index('function obDecode(')
        end = script.index('function obSuggestName(')
        snippet = script[start:end]
        js = snippet + r"""
const assert = require('assert');
const s6 = obParseLink('socks5://u:p@[2001:db8::1]:1080');
assert(s6 && s6.type === 'socks5' && s6.addr === '[2001:db8::1]:1080' && s6.user === 'u' && s6.pass === 'p',
  '应支持带认证的 IPv6 socks5 链接: ' + JSON.stringify(s6));
const h6 = obParseLink('http://[2001:db8::1]:8080');
assert(h6 && h6.type === 'http' && h6.url === 'http://[2001:db8::1]:8080',
  '应支持 IPv6 http 代理链接: ' + JSON.stringify(h6));
const bare6 = obParseLink('[2001:db8::1]:1080');
assert(bare6 && bare6.type === 'socks5' && bare6.addr === '[2001:db8::1]:1080',
  '应支持裸 [IPv6]:port: ' + JSON.stringify(bare6));
assert.strictEqual(obParseLink('1.2.3.4:0'), null, '端口 0 必须被拒绝');
assert.strictEqual(obParseLink('1.2.3.4:70000'), null, '超出 65535 的端口必须被拒绝');
assert.strictEqual(obParseLink('socks5://1.2.3.4:99999'), null, 'socks5 超界端口必须被拒绝');
assert.strictEqual(obParseLink('http://1.2.3.4:70000'), null, 'http 超界端口必须被拒绝');
"""
        self._run_node(js)

    def test_ob_test_form_accepts_ipv6_rejects_bad_port_and_guards_double_click(self):
        """obTestForm 必须允许合法 [IPv6]:port、拒绝 0/70000 端口，且禁用中不重复发请求。"""
        script = portal.SCRIPT
        start = script.index('async function obTestForm()')
        end = script.index("document.querySelectorAll('[data-ob-type]')", start)
        snippet = script[start:end]
        js = r"""
const assert = require('assert');
let calls = 0;
let lastMsg = '';
const location = { pathname: '/' };
function obMsg(text) { lastMsg = text; }
const obEls = {
  type: { value: 'socks5' },
  socksAddr: { value: '1.2.3.4:70000' },
  socksUser: { value: '' },
  socksPass: { value: '' },
  httpUrl: { value: '' },
  httpInsecure: { checked: false },
  btnTest: { disabled: false },
};
globalThis.fetch = async () => {
  calls++;
  return { ok: true, status: 200, json: async () => ({ ok: true, ip: '2001:db8::9' }) };
};
""" + snippet + r"""
(async () => {
  await obTestForm();
  assert.strictEqual(calls, 0, '端口 70000 不得发探测请求');
  obEls.socksAddr.value = '[2001:db8::1]:1080';
  await obTestForm();
  assert.strictEqual(calls, 1, '合法 [IPv6]:port 应正常探测');
  assert(lastMsg.includes('2001:db8::9'), '应展示探测到的出口 IP: ' + lastMsg);
  obEls.btnTest.disabled = true;
  await obTestForm();
  assert.strictEqual(calls, 1, '按钮禁用期间再次触发不得重复发请求');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

    def test_probe_outbound_drops_stale_slow_response(self):
        """probeOutbound 并发触发时，晚到的旧探测结果不得覆盖新探测结果。"""
        script = portal.SCRIPT
        start = script.index('async function probeOutbound(')
        end = script.index('function obResetForm()')
        snippet = script[start:end]
        js = r"""
const assert = require('assert');
const location = { pathname: '/' };
const obEls = { ip: { textContent: '' }, ipNote: { textContent: '' }, probeAddr: { focus() {} } };
const resolvers = [];
globalThis.fetch = () => new Promise(resolve => resolvers.push(resolve));
""" + snippet + r"""
(async () => {
  const slow = probeOutbound('direct', '');
  const fast = probeOutbound('warp', '');
  resolvers[1]({ ok: true, status: 200, json: async () => ({ ok: true, ip: '1.1.1.1' }) });
  await fast;
  assert.strictEqual(obEls.ip.textContent, '1.1.1.1');
  resolvers[0]({ ok: true, status: 200, json: async () => ({ ok: true, ip: '' }) });
  await slow;
  assert.strictEqual(obEls.ip.textContent, '1.1.1.1', '晚到的旧探测失败不得覆盖最新出口 IP');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

    def test_protocol_status_cards_sanitize_non_svg_qr_html(self):
        """协议状态卡片渲染二维码时必须拒绝非 SVG 与含 <script> 的负载，同时放行合法 SVG。"""
        script = portal.SCRIPT
        start = script.index('async function checkRealityStatus() {')
        end = script.index('\n}\n', start) + 3
        snippet = script[start:end]
        js = r"""
const assert = require('assert');
const els = {};
const el = () => ({ style: {}, textContent: '', innerHTML: '', value: '', className: '', classList: { add(){}, remove(){}, toggle(){} }, dataset: {} });
globalThis.document = { getElementById: id => els[id] ||= el(), querySelectorAll: () => [] };
const location = { pathname: '/p/' };
const realityBadge = el(), realityQrBox = el(), realityUriVal = el(), realitySniVal = el(), realityUuidVal = el();
const realityContentBox = el(), btnToggleReality = el(), btnInstallXray = el(), realityPubkeyVal = el(), realityFlowVal = el();
let realityStatusSeq = 0;
function markStatusUnknown() {}
let nextQr = '<img src=x onerror=alert(1)>';
globalThis.fetch = async () => ({
  ok: true,
  json: async () => ({ ok: true, installed: true, active: true, config: { uri: 'vless://x', qr_svg: nextQr, port: 443 } })
});
""" + snippet + r"""
(async () => {
  await checkRealityStatus();
  assert.strictEqual(realityQrBox.innerHTML, '', '非 SVG HTML 负载必须被拦截清空');
  nextQr = '<svg><script>alert(1)</script></svg>';
  await checkRealityStatus();
  assert.strictEqual(realityQrBox.innerHTML, '', '含 <script> 的 SVG 必须被拦截清空');
  nextQr = '<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"></svg>';
  await checkRealityStatus();
  assert(realityQrBox.innerHTML.includes('<svg'), '带 XML 声明的合法 qrencode SVG 应正常渲染');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

    def test_submit_user_form_guards_reentrant_submit(self):
        """submitUserForm 在提交尚未完成期间再次触发不得重复发 POST。"""
        script = portal.SCRIPT
        start = script.index('async function submitUserForm(')
        end = script.index('\n}\n', start) + 3
        snippet = script[start:end]
        js = r"""
const assert = require('assert');
let calls = 0;
let release;
globalThis.FormData = class { constructor() {} entries() { return [][Symbol.iterator](); } [Symbol.iterator]() { return [][Symbol.iterator](); } };
globalThis.alert = () => {};
globalThis.location = { hash: '', reload() {} };
globalThis.fetch = () => {
  calls++;
  return new Promise(r => { release = () => r({ ok: false, status: 400, text: async () => 'err' }); });
};
const form = { getAttribute: () => '/users', querySelector: () => null };
""" + snippet + r"""
(async () => {
  const p1 = submitUserForm(form);
  const p2 = submitUserForm(form);
  assert.strictEqual(calls, 1, '无提交按钮或回车连击时也必须阻止重入提交');
  release();
  await Promise.all([p1, p2]);
  // 结束后应恢复可再次提交
  const p3 = submitUserForm(form);
  assert.strictEqual(calls, 2, '上次提交结束后应允许再次提交');
  release();
  await p3;
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

    def test_wait_for_egress_apply_stops_on_expired_session_and_rule_buttons_lock(self):
        """waitForEgressApply 遇会话过期应立即中止，规则添加/删除按钮应具备防连点禁用保护。"""
        script = portal.SCRIPT
        w_start = script.index('async function waitForEgressApply()')
        w_end = script.index('async function obApi(', w_start)
        w_snippet = script[w_start:w_end]
        js = r"""
const assert = require('assert');
let portalSessionExpired = true;
const location = { pathname: '/' };
let calls = 0;
globalThis.fetch = async () => { calls++; return { ok: true, status: 200, json: async () => ({ applying: true }) }; };
""" + w_snippet + r"""
(async () => {
  let err = null;
  try { await waitForEgressApply(); } catch (e) { err = e; }
  assert(err && String(err.message).includes('登录已失效'), '会话已过期时应立刻抛登录失效而非空等 45 秒');
  assert.strictEqual(calls, 0, '会话已过期时不得继续发起轮询请求');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

        r_start = script.index('if (obEls.rulesList)')
        rules_block = script[r_start:script.index('if (obEls.btnRules)', r_start)]
        self.assertIn('del.disabled = true', rules_block, '删除分流规则期间必须禁用当前按钮防双击')
        self.assertIn('obEls.btnRuleAdd.disabled = true', rules_block, '添加分流规则期间必须禁用按钮防双击')


if __name__ == '__main__':
    unittest.main()
