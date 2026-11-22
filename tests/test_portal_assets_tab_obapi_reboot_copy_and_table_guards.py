"""回归测试：portal_assets.py 标签选择器注入、obApi 401/null、重启刷新锁、复制兜底与用户表空搜索。"""
from __future__ import annotations

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import portal_assets  # noqa: E402

NODE = shutil.which("node")


def _extract_fn(src: str, signature: str, end_marker: str) -> str:
    start = src.index(signature)
    end = src.index(end_marker, start)
    return src[start:end]


@unittest.skipUnless(NODE, "需要 Node.js 执行前端回归断言")
class PortalAssetsTabObApiRebootCopyTableGuardTests(unittest.TestCase):
    """在 Node.js 中真实执行并验证 5 组前端稳定性与安全边界。"""

    def _run_node(self, js_code: str) -> None:
        proc = subprocess.run(
            [NODE, "-e", js_code],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f"Node 执行失败:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

    def test_switch_tab_rejects_malicious_hash_without_clearing_active_tab(self):
        """非法 tabId（含引号/方括号）不得抛选择器异常，也不得把当前已激活标签清成空白。"""
        fn_src = _extract_fn(portal_assets.SCRIPT, "function switchTab(tabId, subId) {", "document.querySelectorAll('[data-tab]')")
        js = f"""
const assert = require('assert');
let activeRemoved = false;
let queryCalledWith = [];
const makeEl = () => ({{
  classList: {{
    remove(cls) {{ if (cls === 'active') activeRemoved = true; }},
    add() {{}},
  }},
  querySelectorAll() {{ return []; }},
  querySelector(sel) {{
    queryCalledWith.push(sel);
    if (sel.includes('"]]')) throw new Error('DOMException: invalid selector');
    return null;
  }},
  parentElement: null,
}});
const validBtn = makeEl();
const validPane = makeEl();
global.document = {{
  querySelectorAll() {{ return [validBtn]; }},
  querySelector(sel) {{
    queryCalledWith.push(sel);
    if (sel.includes('"]]')) throw new Error('DOMException: invalid selector');
    return sel === '[data-tab="users"]' ? validBtn : null;
  }},
  getElementById(id) {{ return id === 'pane-users' ? validPane : null; }},
}};
global.history = {{ replaceState() {{}} }};
global.switchSubtab = () => {{}};
{fn_src}

// 传入带选择器注入字符的 tabId：不得抛错，且绝不能先清空现有 active 标签
switchTab('users"]]');
assert.strictEqual(activeRemoved, false, '非法 tabId 不得清空当前激活标签');
assert.strictEqual(queryCalledWith.length, 0, '非法 tabId 应在拼接选择器前直接拦截');

// 传入不存在的合法 tabId：也不得清空现有 active 标签
switchTab('nonexistent');
assert.strictEqual(activeRemoved, false, '不存在的 tabId 不得先把页面清成空白');
"""
        self._run_node(js)

    def test_ob_api_marks_session_expired_on_401_and_handles_null_json(self):
        """obApi 遇 401 须置位 portalSessionExpired；响应为 JSON null 时不得抛 TypeError。"""
        fn_src = _extract_fn(portal_assets.SCRIPT, "async function obApi(action, params) {", "let OB_STATE =")
        js = f"""
const assert = require('assert');
global.location = {{ pathname: '/p/' }};
let portalSessionExpired = false;
global.waitForEgressApply = async () => ({{}});
let nextResp = null;
global.fetch = async () => nextResp;
{fn_src}

(async () => {{
  // 1) 401 时必须置位 portalSessionExpired 并抛中文登录失效提示
  nextResp = {{ ok: false, status: 401, json: async () => ({{ error: 'unauthorized' }}) }};
  let err1 = null;
  try {{ await obApi('add', {{}}); }} catch (e) {{ err1 = e; }}
  assert(err1, '401 必须抛错');
  assert.strictEqual(portalSessionExpired, true, '401 后必须置位 portalSessionExpired');
  assert(err1.message.includes('登录'), '401 应提示中文登录过期，实际: ' + err1.message);

  // 2) JSON 为 null 时不得抛 TypeError
  portalSessionExpired = false;
  nextResp = {{ ok: true, status: 200, json: async () => null }};
  let err2 = null;
  try {{ await obApi('add', {{}}); }} catch (e) {{ err2 = e; }}
  assert(err2, 'JSON null 必须抛业务错误');
  assert(!(err2 instanceof TypeError), 'JSON null 不得触发未处理的 TypeError: ' + err2);
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
        self._run_node(js)

    def test_reboot_button_stays_disabled_while_reloading_and_wait_portal_back_bounds_args(self):
        """服务器恢复触发 location.reload() 前不得提前解锁重启按钮；waitPortalBack 须校验参数边界并兼容缺 AbortController。"""
        wait_src = _extract_fn(portal_assets.SCRIPT, "async function waitPortalBack(", "if (btnRebootServer) {")
        reboot_src = _extract_fn(portal_assets.SCRIPT, "if (btnRebootServer) {", "// 多用户表")
        js = f"""
const assert = require('assert');
let reloaded = false;
let btnDisabledAtReload = null;
let clickHandler = null;
const btnRebootServer = {{
  disabled: false,
  textContent: 'init',
  addEventListener(ev, fn) {{ if (ev === 'click') clickHandler = fn; }},
}};
global.location = {{
  pathname: '/p/',
  reload() {{ reloaded = true; btnDisabledAtReload = btnRebootServer.disabled; }},
}};
global.showConfirm = async () => true;
global.alert = () => {{}};
global.fetch = async (url) => {{
  if (url.endsWith('reboot-server')) return {{ ok: true, status: 200, json: async () => ({{ ok: true }}) }};
  return {{ ok: true, status: 200 }};
}};
// 模拟无 AbortController 环境
const origAC = global.AbortController;
global.AbortController = undefined;

// 加速 setInterval 以便在测试中瞬间跑完 25 秒倒计时
const origSetInterval = global.setInterval;
global.setInterval = (fn, _ms) => origSetInterval(fn, 1);

{wait_src}
{reboot_src}

(async () => {{
  // 1) waitPortalBack 在无 AbortController 且传 NaN/0 参数时不得死循环或报错
  const okBack = await waitPortalBack(NaN, 0);
  assert.strictEqual(okBack, true, 'waitPortalBack 应兼容非法超时/间隔并正常探测成功');

  // 2) 重启恢复触发 reload 时按钮必须保持禁用
  await clickHandler();
  await new Promise(r => setTimeout(r, 200));
  assert.strictEqual(reloaded, true, '恢复后应调用 location.reload()');
  assert.strictEqual(btnDisabledAtReload, true, '触发 reload 时重启按钮必须保持 disabled 防止重复重启');
  global.AbortController = origAC;
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
        self._run_node(js)

    def test_copy_with_feedback_cleans_textarea_on_error_and_user_table_handles_missing_search_attr(self):
        """copyWithFeedback 异常时仍须清理临时 textarea；initUserTable 行缺 data-search 时不得抛 TypeError。"""
        copy_src = _extract_fn(portal_assets.SCRIPT, "function copyWithFeedback(", "if (btnCopyRealityUri)")
        table_src = _extract_fn(portal_assets.SCRIPT, "(function initUserTable() {", "checkBbrStatus();")
        js = f"""
const assert = require('assert');
let taRemoved = false;
let alerted = '';
global.alert = (m) => {{ alerted = m; }};
global.navigator = {{}};
global.document = {{
  body: {{ appendChild() {{}} }},
  createElement() {{
    return {{
      value: '',
      style: {{}},
      select() {{ throw new Error('select failed'); }},
      remove() {{ taRemoved = true; }},
    }};
  }},
  execCommand() {{ return false; }},
}};
{copy_src}

const btn = {{ dataset: {{}}, textContent: '复制' }};
copyWithFeedback('hello', btn, '已复制');
assert.strictEqual(taRemoved, true, 'ta.select() 抛异常时仍必须在 finally 中移除临时 textarea');

// 验证 initUserTable 缺 data-search 时输入关键词不崩溃
let inputHandler = null;
const rows = [
  {{ dataset: {{ state: 'active' }}, style: {{ display: '' }} }},
  {{ dataset: {{ state: 'active', search: 'alice' }}, style: {{ display: '' }} }},
];
const searchEl = {{ value: 'ali', addEventListener(ev, fn) {{ if (ev === 'input') inputHandler = fn; }} }};
const filterEl = {{ value: 'all', addEventListener() {{}} }};
global.document = {{
  getElementById(id) {{
    if (id === 'user-tbody') return {{ querySelectorAll: () => rows }};
    if (id === 'user-search') return searchEl;
    if (id === 'user-filter') return filterEl;
    if (id === 'user-count') return {{ textContent: '' }};
    if (id === 'user-pager') return {{ textContent: '', appendChild() {{}} }};
    return null;
  }},
  createElement() {{ return {{ type: '', className: '', textContent: '', disabled: false, addEventListener() {{}} }}; }},
}};
{table_src}
assert.strictEqual(rows[0].style.display, 'none', '缺 data-search 的行应安全判定不匹配而非抛异常');
assert.strictEqual(rows[1].style.display, '', '匹配的行应正常显示');
"""
        self._run_node(js)


if __name__ == "__main__":
    unittest.main()
