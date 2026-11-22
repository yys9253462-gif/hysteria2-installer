"""回归测试：renderCore 原型链键隔离、probeOutbound/awgPost 401 置位与非串 IP、核心装卸判空及用户弹窗布尔/NaN 渲染防护。"""
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


def _extract(src: str, start_marker: str, end_marker: str) -> str:
    s = src.index(start_marker)
    e = src.index(end_marker, s)
    return src[s:e]


@unittest.skipUnless(NODE, "需要 Node.js 执行前端回归测试")
class PortalAssetsCoreProbeAwgModalGuardTests(unittest.TestCase):
    """验证第五十八批第 4 项的前端稳定性与安全边界。"""

    def _run_node(self, js_code: str) -> None:
        proc = subprocess.run(
            [NODE, "-e", js_code],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f"Node 执行失败:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

    def test_render_core_isolates_prototype_state_key_and_filters_used_by(self):
        """renderCore 遇 state='constructor' 不得命中 Object.prototype 渲染出 undefined，且过滤 used_by 空脏项。"""
        block = _extract(portal_assets.SCRIPT, "const CORE_STATE_TEXT = {", "let coresSeq = 0;")
        js = f"""
const assert = require('assert');
function makeNode(tag) {{
  return {{
    tag, className: '', textContent: '', style: {{}}, children: [],
    appendChild(c) {{ this.children.push(c); }},
    addEventListener() {{}},
  }};
}}
global.document = {{
  createElement: (tag) => makeNode(tag),
  createTextNode: (t) => ({{ textContent: t }}),
}};
{block}

const card = renderCore({{
  id: 'xray', name: 'Xray', installed: true, state: 'constructor',
  version: '26.3.27', service: 'xray', used_by: ['Reality', null, '', 'VMess'],
}});
const pill = card.children[0].children[1];
assert(!pill.textContent.includes('undefined'), '原型键 constructor 不得渲染出 undefined，实际: ' + pill.textContent);
assert.strictEqual(pill.style.background, '#f1efe8');

const cardUndef = renderCore({{
  id: 'sb', name: 'sing-box', installed: true, state: undefined,
  version: '1.12.0', service: 'hy2-anytls', used_by: ['AnyTLS', null],
}});
const pillUndef = cardUndef.children[0].children[1];
assert(!pillUndef.textContent.includes('undefined'), '缺失 state 不得渲染出 undefined，实际: ' + pillUndef.textContent);

const usedText = card.children[1].children[2].children[1].textContent;
assert.strictEqual(usedText, 'Reality、VMess', 'used_by 应过滤空项与非字符串，实际: ' + usedText);
"""
        self._run_node(js)

    def test_probe_outbound_and_awg_post_mark_session_expired_on_401_and_guard_non_str_ip(self):
        """probeOutbound 与 awgPost 收到 401 须置位 portalSessionExpired；probeOutbound 拒非字符串 ip。"""
        probe_src = _extract(portal_assets.SCRIPT, "async function probeOutbound(", "function obResetForm()")
        awg_src = _extract(portal_assets.SCRIPT, "function awgPost(", "function setAwgBadge(")
        js = f"""
const assert = require('assert');
global.location = {{ pathname: '/p/' }};
let portalSessionExpired = false;
const obEls = {{ ip: {{ textContent: '' }}, ipNote: {{ textContent: '' }} }};
let nextResp = null;
global.fetch = async () => nextResp;
{probe_src}
{awg_src}

(async () => {{
  // 1) probeOutbound 401 置位 portalSessionExpired
  nextResp = {{ ok: false, status: 401, json: async () => ({{ error: 'unauthorized' }}) }};
  await probeOutbound('direct', '');
  assert.strictEqual(portalSessionExpired, true, 'probeOutbound 遇 401 必须置位 portalSessionExpired');
  assert(obEls.ipNote.textContent.includes('登录'), 'probeOutbound 401 应给中文登录失效提示: ' + obEls.ipNote.textContent);

  // 2) probeOutbound 收到非字符串 ip 不得渲染 [object Object]
  portalSessionExpired = false;
  nextResp = {{ ok: true, status: 200, json: async () => ({{ ok: true, ip: {{ bad: 1 }} }}) }};
  await probeOutbound('direct', '');
  assert(!obEls.ip.textContent.includes('[object'), '非字符串 ip 不得渲染为 [object Object]: ' + obEls.ip.textContent);
  assert.strictEqual(obEls.ip.textContent, '探测失败');

  // 3) awgPost 401 置位 portalSessionExpired 且 params 为 null 不崩溃
  portalSessionExpired = false;
  nextResp = {{ ok: false, status: 401, json: async () => ({{ error: 'expired' }}) }};
  const r = await awgPost('manage-awg', null);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(portalSessionExpired, true, 'awgPost 遇 401 必须置位 portalSessionExpired');
  assert(r.error.includes('登录'), 'awgPost 401 应返回中文登录过期提示: ' + r.error);
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
        self._run_node(js)

    def test_user_modal_guards_bool_ip_limit_and_invalid_expires_at(self):
        """用户连接弹窗对 ip_limit=true 不得显示 'true IP'，对非法 expires_at 不得显示 'Invalid Date'。"""
        modal_src = _extract(portal_assets.SCRIPT, "document.querySelectorAll('.btn-user-connect')", "/* ==================== AmneziaWG")
        ob_esc_src = _extract(portal_assets.SCRIPT, "function obEsc(", "function obMsg(")
        fmt_src = _extract(portal_assets.SCRIPT, "function fmtUnits(", "function fmtSpeed(")
        banner_src = _extract(portal_assets.SCRIPT, "function userStatusBanner(", "document.querySelectorAll('.btn-user-connect')")
        js = f"""
const assert = require('assert');
let clickHandler = null;
const btn = {{
  dataset: {{ uid: 'u1', token: 'tok', key: 'k1' }},
  addEventListener(ev, fn) {{ if (ev === 'click') clickHandler = fn; }},
}};
let userModalSeq = 0;
let portalSessionExpired = false;
const uModal = {{ classList: {{ add() {{}} }} }};
const uModalClose = {{}};
const uModalTitle = {{ textContent: '' }};
const uModalSub = {{ textContent: '' }};
const uModalBody = {{ innerHTML: '', querySelectorAll: () => [] }};
global.focusModal = () => {{}};
global.location = {{ origin: 'https://node.example.com:8443', pathname: '/tok/' }};
global.document = {{ querySelectorAll: () => [btn], getElementById: () => null }};
global.fetch = async () => ({{
  ok: true, status: 200,
  json: async () => ({{
    ok: true,
    uri: 'hy2://p@h:443',
    clash: 'proxies: []',
    sing_box: '{{}}',
    traffic_used: 1024,
    traffic_limit: true,
    ip_limit: true,
    expires_at: 'not-a-timestamp',
  }}),
}});
{ob_esc_src}
{fmt_src}
{banner_src}
{modal_src}

(async () => {{
  await clickHandler();
  assert(!uModalBody.innerHTML.includes('true IP'), '布尔 ip_limit 不得渲染成 true IP:\\n' + uModalBody.innerHTML);
  assert(!uModalBody.innerHTML.includes('Invalid Date'), '非法 expires_at 不得渲染成 Invalid Date:\\n' + uModalBody.innerHTML);
  assert(uModalBody.innerHTML.includes('(不限)'), '布尔 traffic_limit 不得按正限额渲染');
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
        self._run_node(js)


if __name__ == "__main__":
    unittest.main()
