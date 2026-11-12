"""出站面板与代理表格加载失败时不停在「加载中」（2026-11-12 修）。

旧实现 loadOutbounds / loadProxyServices 失败时直接 return：模式说明、出站列表、分流规则、
代理表格永远显示「加载中...」，用户以为还没配置。已经渲染过的数据不能被之后的失败清空。
从 portal.SCRIPT 摘出真实函数，用 node 模拟 HTTP 500 / ok:false / 网络中断。
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')

HARNESS = r"""
const assert = require('assert');
function el(tag, text) {
  const e = {tagName: tag, style: {}, dataset: {}, classList: {add(){}, remove(){}, toggle(){}},
             children: [], _html: '', get textContent() { return this._html.replace(/<[^>]*>/g, ''); },
             set textContent(v) { this._html = String(v); }, get innerHTML() { return this._html; },
             set innerHTML(v) { this._html = String(v); },
             querySelector(sel) { const m = /colspan="(\d+)"/.exec(this._html);
               return sel === 'td' && m ? {getAttribute: () => m[1]} : null; },
             querySelectorAll() { return []; }, addEventListener() {}};
  e._html = text;
  return e;
}
globalThis.document = {getElementById: () => null, querySelectorAll: () => []};
const location = {pathname: '/t/'};
const MODES = {
  http500: () => Promise.resolve(new Response('<html>Internal Server Error</html>', {status: 500})),
  okfalse: () => Promise.resolve(new Response(JSON.stringify({ok: false, error: '磁盘已满'}))),
  network: () => Promise.reject(new TypeError('Failed to fetch')),
};
"""

OUTBOUND_CHECK = r"""
(async () => {
  for (const [mode, impl] of Object.entries(MODES)) {
    obEls.modeNote = el('P', '加载中...');
    obEls.list = el('DIV', '<span class="ob-empty">加载中...</span>');
    obEls.rulesList = el('DIV', '<span class="ob-empty">加载中...</span>');
    globalThis.fetch = impl;
    await loadOutbounds();
    for (const key of ['modeNote', 'list', 'rulesList']) {
      const text = obEls[key].textContent;
      assert.ok(!text.includes('加载中'), mode + ': ' + key + ' stuck at ' + text);
      assert.ok(text.includes('出站配置加载失败'), mode + ': ' + key + ' shows ' + text);
    }
  }
  obEls.list = el('DIV', '<div class="ob-item">warp_socks</div>');
  globalThis.fetch = MODES.http500;
  await loadOutbounds();
  assert.ok(obEls.list.textContent.includes('warp_socks'), 'a later failed refresh wiped the rendered list');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""

PROXY_CHECK = r"""
(async () => {
  for (const [mode, impl] of Object.entries(MODES)) {
    proxyTbody = el('TBODY', '<tr><td colspan="6">正在加载代理服务...</td></tr>');
    globalThis.fetch = impl;
    await loadProxyServices();
    const text = proxyTbody.textContent;
    assert.ok(!text.includes('正在加载'), mode + ': table stuck at ' + text);
    assert.ok(text.includes('代理服务列表加载失败'), mode + ': table shows ' + text);
    assert.ok(proxyTbody.innerHTML.includes('colspan="6"'), mode + ': column span lost');
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


WARP_CHECK = r"""
(async () => {
  const fresh = () => {
    warpRulesCount = el('SPAN', '加载中...');
    warpTagsCloud = el('DIV', '正在拉取规则...');
  };
  fresh();
  globalThis.fetch = () => Promise.resolve(new Response(JSON.stringify(
    {ok: true, installed: false, enabled: false, rules: ['openai.com', 'claude.ai']})));
  await checkWarpStatus();
  assert.strictEqual(warpRulesCount.textContent, '2 个已配置', 'count stuck at ' + warpRulesCount.textContent);
  assert.ok(warpTagsCloud.innerHTML.includes('openai.com'), 'rules not listed: ' + warpTagsCloud.textContent);
  fresh();
  globalThis.fetch = MODES.http500;
  await checkWarpStatus();
  assert.strictEqual(warpRulesCount.textContent, '数量未知');
  assert.ok(warpTagsCloud.textContent.includes('分流规则读取失败'), warpTagsCloud.textContent);
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


def _block(header):
    script = portal.SCRIPT
    if header not in script:
        return ''
    start = script.index(header)
    return script[start:script.index('\n}\n', start) + 3]


def run_node(source):
    return subprocess.run([NODE, '-e', source], capture_output=True, text=True, encoding='utf-8', timeout=30)


@unittest.skipUnless(NODE, 'requires node')
class ListLoadFailureTests(unittest.TestCase):
    def helpers(self):
        return _block('function markStatusUnknown(') + _block('function markLoadFailed(') + _block('function obEsc(')

    def test_outbound_panel_reports_a_failed_load(self):
        stubs = ('var obEls = {}; var OB_STATE = {}; function obSetModeUI() {} function renderOutboundList() {}\n'
                 'function renderOutboundRules() {} function obMsg() {}\n')
        r = run_node(HARNESS + stubs + self.helpers() + _block('async function loadOutbounds()') + OUTBOUND_CHECK)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_warp_rules_render_when_not_installed_and_report_a_failed_load(self):
        stubs = ('var warpBadge = el("SPAN", "检测中..."); var btnInstallWarp = el("BUTTON", "");\n'
                 'var btnToggleWarp = el("BUTTON", ""); var warpRulesCount = null; var warpTagsCloud = null;\n'
                 'let warpStatusSeq = 0;\n')
        source = (HARNESS + stubs + self.helpers() + _block('function markWarpRulesFailed(')
                  + _block('function renderWarpRules(') + _block('async function checkWarpStatus()') + WARP_CHECK)
        r = run_node(source)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_proxy_table_reports_a_failed_load(self):
        stubs = 'var proxyTbody = null; var gostBadge = el("SPAN", "检测中..."); var curProxyServerHost = "";\n'
        r = run_node(HARNESS + stubs + self.helpers() + _block('async function loadProxyServices()') + PROXY_CHECK)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
