import importlib.util
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS_PATH = ROOT / 'portal_assets.py'


def _load_script():
    spec = importlib.util.spec_from_file_location('portal_assets_batch56_item4', ASSETS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SCRIPT


def _extract_js_function(script, fn_name):
    m = re.search(rf'(?:async\s+)?function\s+{re.escape(fn_name)}\s*\([^)]*\)\s*\{{', script)
    if not m:
        raise AssertionError(f'未找到前端函数: {fn_name}')
    start = m.start()
    idx = m.end() - 1
    depth = 0
    in_str = None
    escaped = False
    while idx < len(script):
        ch = script[idx]
        if in_str:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in ('"', "'", '`'):
                in_str = ch
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return script[start:idx + 1]
        idx += 1
    raise AssertionError(f'函数括号未闭合: {fn_name}')


class PortalAssetsAsyncSeqReentryAndSvgGuardTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), '需要 node 执行前端逻辑验证')
    def test_load_outbounds_proxy_services_and_awg_state_drop_stale_responses(self):
        script = _load_script()
        fn_ob = _extract_js_function(script, 'loadOutbounds')
        fn_px = _extract_js_function(script, 'loadProxyServices')
        fn_awg = _extract_js_function(script, 'loadAwgState')
        js = f"""
const location = {{ pathname: '/p/' }};
const obEls = {{ list: {{ textContent: '' }}, modeNote: {{}}, rulesList: {{}} }};
let OB_STATE = {{ mode: 'rules', outbounds: [], rules: [], builtin: [] }};
let obRendered = [];
function obSetModeUI(m) {{}}
function renderOutboundList(list) {{ obRendered.push(list); }}
function renderOutboundRules(r, o, b) {{}}
function obMsg() {{}}
function markLoadFailed() {{}}
function markStatusUnknown() {{}}

const proxyTbody = {{ innerHTML: '' }};
const gostBadge = {{ textContent: '', style: {{}} }};
const btnInstallGost = null;
let curProxyServerHost = '1.2.3.4';
function obEsc(s) {{ return String(s || ''); }}

const awgBadge = {{ textContent: '', style: {{}} }};
const awgMetaBox = null, awgPanel = null, awgInstallBox = null, btnInstallAwg = null;
const awgEndpointInput = null, awgPeerEndpoint = null, awgMetaChip = null;
const awgLineSelect = null, awgMetaLine = null, awgMetaPort = null, awgMetaPeers = null;
let awgCurrentEndpoint = '', awgCurrentLine = '3';
let awgPeersHistory = [];
function setAwgBadge(t) {{ awgBadge.textContent = t; }}
function renderAwgPeers(peers) {{ awgPeersHistory.push(peers); }}

const resolvers = [];
function fetch(url) {{
  return new Promise(resolve => resolvers.push({{ url, resolve }}));
}}

{fn_ob}
{fn_px}
{fn_awg}

(async () => {{
  // 1. loadOutbounds: 第一个响应晚到且含旧列表，不应覆盖第二个新响应
  const p1 = loadOutbounds();
  const p2 = loadOutbounds();
  resolvers[1].resolve({{ ok: true, status: 200, json: async () => ({{ ok: true, mode: 'global', outbounds: [{{ name: 'new' }}], rules: 'bad-not-array', builtin: [] }}) }});
  await p2;
  resolvers[0].resolve({{ ok: true, status: 200, json: async () => ({{ ok: true, mode: 'rules', outbounds: [{{ name: 'stale' }}], rules: [], builtin: [] }}) }});
  await p1;

  // 2. loadProxyServices: 晚到旧响应不应覆盖新响应
  const px1 = loadProxyServices();
  const px2 = loadProxyServices();
  resolvers[3].resolve({{ ok: true, status: 200, json: async () => ({{ ok: true, gost_installed: true, gost_active: true, services: [] }}) }});
  await px2;
  resolvers[2].resolve({{ ok: true, status: 200, json: async () => ({{ ok: true, gost_installed: false, gost_active: false, services: [] }}) }});
  await px1;

  // 3. loadAwgState: 晚到旧响应不应覆盖新客户端列表
  const a1 = loadAwgState();
  const a2 = loadAwgState();
  resolvers[5].resolve({{ ok: true, status: 200, json: async () => ({{ ok: true, installed: true, active: true, peers: [{{ name: 'new-peer' }}] }}) }});
  await a2;
  resolvers[4].resolve({{ ok: true, status: 200, json: async () => ({{ ok: true, installed: true, active: false, peers: [{{ name: 'old-peer' }}] }}) }});
  await a1;

  console.log(JSON.stringify({{
    obMode: OB_STATE.mode,
    obRulesIsArray: Array.isArray(OB_STATE.rules),
    obLast: obRendered[obRendered.length - 1],
    gostBadge: gostBadge.textContent,
    awgLast: awgPeersHistory[awgPeersHistory.length - 1],
  }}));
}})();
"""
        proc = subprocess.run(['node', '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout.strip())
        self.assertEqual(res['obMode'], 'global')
        self.assertTrue(res['obRulesIsArray'])
        self.assertEqual(res['obLast'], [{'name': 'new'}])
        self.assertIn('运行中', res['gostBadge'])
        self.assertEqual(res['awgLast'], [{'name': 'new-peer'}])

    @unittest.skipUnless(shutil.which('node'), '需要 node 执行前端逻辑验证')
    def test_install_and_uninstall_core_recheck_disabled_after_confirm(self):
        script = _load_script()
        fn_inst = _extract_js_function(script, 'installCore')
        fn_uninst = _extract_js_function(script, 'uninstallCore')
        js = f"""
const location = {{ pathname: '/p/' }};
let fetchCount = 0;
async function fetch() {{ fetchCount++; return {{ ok: true, status: 200, json: async () => ({{ ok: true }}) }}; }}
function showToast() {{}}
function alert() {{}}
async function loadCores() {{}}
const confirmResolvers = [];
function showConfirm() {{ return new Promise(r => confirmResolvers.push(r)); }}

{fn_inst}
{fn_uninst}

(async () => {{
  const btn = {{ disabled: false, textContent: '安装' }};
  const core = {{ id: 'xray', name: 'Xray', installed: false }};
  // 模拟确认弹窗期间二次触发
  const c1 = installCore(core, btn);
  const c2 = installCore(core, btn);
  confirmResolvers[0](true);
  confirmResolvers[1](true);
  await Promise.all([c1, c2]);
  const instCount = fetchCount;

  fetchCount = 0;
  confirmResolvers.length = 0;
  const btn2 = {{ disabled: false, textContent: '卸载' }};
  const u1 = uninstallCore(core, btn2);
  const u2 = uninstallCore(core, btn2);
  confirmResolvers[0](true);
  confirmResolvers[1](true);
  await Promise.all([u1, u2]);
  console.log(JSON.stringify({{ instCount, uninstCount: fetchCount }}));
}})();
"""
        proc = subprocess.run(['node', '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout.strip())
        self.assertEqual(res['instCount'], 1)
        self.assertEqual(res['uninstCount'], 1)

    def test_protocol_toggles_and_svg_filters_are_hardened(self):
        script = _load_script()
        # 5 个协议开关 + 重置密钥在确认弹窗返回后均须二次检查 disabled
        for token in (
            'if (!action || btnToggleReality.disabled) return;',
            'if (!confirmed || btnResetRealityKeys.disabled) return;',
            'if (!action || btnToggleVmess.disabled) return;',
            'if (!action || btnToggleVlessenc.disabled) return;',
            'if (!action || btnToggleAnytls.disabled) return;',
            'if (!action || btnToggleTuic.disabled) return;',
        ):
            self.assertIn(token, script, f'缺少确认后二次防重入保护: {token}')
        # 所有 qr_svg 注入点均须校验以 <svg 开头并拦截 on*= 事件属性与 foreignObject
        self.assertGreaterEqual(script.count('<svg\\b/i.test(json.qr_svg.trim())'), 1)
        self.assertGreaterEqual(script.count('foreignObject'), 6)


if __name__ == '__main__':
    unittest.main()
