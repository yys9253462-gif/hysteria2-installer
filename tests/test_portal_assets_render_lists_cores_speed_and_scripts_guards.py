"""回归测试：出站与规则列表脏数据容错、核心卡片非数组 used_by 防护、实时网速原型键隔离与重启/登录脚本健壮性。"""

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
class PortalAssetsRenderListsCoresSpeedAndScriptsGuardsTests(unittest.TestCase):
    def _run_node(self, code):
        proc = subprocess.run(
            [NODE, '-e', code],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_render_outbound_list_and_rules_ignore_null_and_non_array_inputs(self):
        """renderOutboundList 与 renderOutboundRules 遇 null 元素或非数组输入不得抛 TypeError 或渲染出 'null'。"""
        script = portal.SCRIPT
        start = script.index('const OB_TYPE_LABEL = {')
        end = script.index('function obSetModeUI(', start)
        snippet = script[start:end]
        js = r"""
const assert = require('assert');
const obEls = {
  list: { innerHTML: '' },
  count: { textContent: '' },
  rulesList: { innerHTML: '' },
  rulesCount: { textContent: '' },
  ruleOutbound: { innerHTML: '', value: '' },
};
""" + snippet + r"""
renderOutboundList(null);
assert.strictEqual(obEls.count.textContent, '0 个');
renderOutboundList([null, 'bad', { name: 'p1', type: 'socks5', addr: '1.2.3.4:1080' }]);
assert.strictEqual(obEls.count.textContent, '1 个');
assert(obEls.list.innerHTML.includes('p1'));

renderOutboundRules([null, undefined, '', { domain: '' }, { domain: 'example.com', outbound: 'p1' }], null, null);
assert.strictEqual(obEls.rulesCount.textContent, '1 条');
assert(!obEls.rulesList.innerHTML.includes('>null<'), '不得把 null 渲染成规则域名');
assert(obEls.rulesList.innerHTML.includes('example.com'));
"""
        self._run_node(js)

    def test_render_core_handles_non_array_used_by_and_missing_fields(self):
        """renderCore 遇非数组 used_by（字符串/null/对象）不得抛 TypeError。"""
        script = portal.SCRIPT
        start = script.index('const CORE_STATE_TEXT = {')
        end = script.index('let coresSeq = 0;', start)
        snippet = script[start:end]
        js = r"""
const assert = require('assert');
function mkEl(tag) {
  return {
    tag, className: '', textContent: '', style: {}, type: '', children: [],
    appendChild(c) { this.children.push(c); return c; },
    addEventListener() {},
  };
}
globalThis.document = {
  createElement: mkEl,
  createTextNode: text => ({ text }),
};
""" + snippet + r"""
const card = renderCore({ name: 'Xray', installed: true, state: 'active', version: '1.8', service: 'xray', used_by: 'Reality' });
assert(card && card.children.length > 0, '非数组 used_by 时仍应成功渲染核心卡片');
"""
        self._run_node(js)

    def test_poll_traffic_speed_ignores_prototype_keys_and_non_object_users(self):
        """pollTrafficSpeed 不得把用户名 'constructor'/'toString' 误命中 Object 原型属性，且须兼容异常 users 字段。"""
        script = portal.SCRIPT
        f_start = script.index('function fmtUnits(')
        f_end = script.index('setInterval(() => { if (!document.hidden', f_start)
        snippet = script[f_start:f_end]
        js = r"""
const assert = require('assert');
const speedRxEl = { textContent: '' };
const speedTxEl = { textContent: '' };
const rxTagEl = { className: '' };
const txTagEl = { className: '' };
const usageEl = { dataset: { userUsage: 'constructor' }, textContent: 'ORIG', title: '' };
const speedBadge = { dataset: { userSpeed: 'constructor' }, textContent: '', className: '' };
let portalSessionExpired = false;
const location = { pathname: '/' };
globalThis.document = {
  hidden: false,
  getElementById: () => ({ textContent: '' }),
  querySelectorAll: sel => sel === '[data-user-usage]' ? [usageEl] : [speedBadge],
};
globalThis.fetch = async () => ({
  ok: true,
  json: async () => ({ ok: true, node_rx: 2048, node_tx: 0, total_used_bytes: 1024, users: {} })
});
""" + snippet + r"""
(async () => {
  await pollTrafficSpeed();
  assert.strictEqual(usageEl.textContent, 'ORIG', '不存在的用户名 constructor 不得命中 Object.prototype');
  assert.strictEqual(speedBadge.className, 'speed-badge');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        self._run_node(js)

    def test_reboot_recheck_and_login_script_guards(self):
        """重启与重检按钮须防双击，LOGIN_SCRIPT 须对 parentElement 判空。"""
        script = portal.SCRIPT
        reboot_block = script[script.index('if (btnRebootServer)'):script.index('(function initUserTable()')]
        self.assertIn('if (btnRebootServer.disabled) return;', reboot_block)
        recheck_block = script[script.index('if (btnRecheckUpdate)'):script.index('checkVersions();')]
        self.assertIn('if (btnRecheckUpdate.disabled) return;', recheck_block)
        self.assertIn('btn.parentElement && btn.parentElement.querySelector', portal.LOGIN_SCRIPT)


if __name__ == '__main__':
    unittest.main()
