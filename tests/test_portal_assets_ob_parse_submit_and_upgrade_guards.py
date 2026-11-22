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
    spec = importlib.util.spec_from_file_location('portal_assets_batch57_item4', ASSETS_PATH)
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


class PortalAssetsObParseSubmitAndUpgradeGuardTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), '需要 node 执行前端逻辑验证')
    def test_ob_parse_link_auto_name_and_suggest_name_bounds(self):
        script = _load_script()
        fn_decode = _extract_js_function(script, 'obDecode')
        fn_parse = _extract_js_function(script, 'obParseLink')
        fn_suggest = _extract_js_function(script, 'obSuggestName')
        fn_auto = _extract_js_function(script, 'obAutoName')
        js = f"""
const takenList = [];
const base29 = 'socks_' + 'a'.repeat(23);
takenList.push('socks_' + 'a'.repeat(26));
for (let i = 2; i <= 105; i++) takenList.push(base29 + '_' + i);
const document = {{
  querySelectorAll: () => takenList.map(v => ({{ dataset: {{ obEdit: v }} }})),
}};
let obNameAuto = true;
const obEls = {{
  name: {{ value: '', readOnly: false }},
  type: {{ value: 'http' }},
  httpUrl: {{ value: 'http://[2001:db8::1]:8080' }},
  socksAddr: {{ value: '' }},
}};
{fn_decode}
{fn_parse}
{fn_suggest}
{fn_auto}

const badLeadingZero = obParseLink('socks5://1.2.3.4:08080');
const goodSocks = obParseLink('socks5://1.2.3.4:1080');
obAutoName();
const ipv6HttpName = obEls.name.value;
const longName = obSuggestName('socks5', 'a'.repeat(40));
console.log(JSON.stringify({{
  badLeadingZero,
  goodPortOk: !!(goodSocks && goodSocks.addr === '1.2.3.4:1080'),
  ipv6HttpName,
  longNameLen: longName.length,
}}));
"""
        proc = subprocess.run(['node', '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout.strip())
        self.assertIsNone(res['badLeadingZero'], 'obParseLink 不应放行前导零端口 08080')
        self.assertTrue(res['goodPortOk'])
        self.assertIn('db8', res['ipv6HttpName'], f'HTTP IPv6 代理名被截断: {res["ipv6HttpName"]}')
        self.assertLessEqual(res['longNameLen'], 32, f'obSuggestName 超过 32 字符上限: {res["longNameLen"]}')

    @unittest.skipUnless(shutil.which('node'), '需要 node 执行前端逻辑验证')
    def test_submit_user_form_handles_401_and_truncates_html_error_body(self):
        script = _load_script()
        fn_submit = _extract_js_function(script, 'submitUserForm')
        js = f"""
const alerts = [];
let portalSessionExpired = false;
function alert(msg) {{ alerts.push(String(msg)); }}
class FormData {{ constructor() {{}} entries() {{ return []; }} }}
const location = {{ hash: '', reload: () => {{}} }};
let nextRes = null;
async function fetch() {{ return nextRes; }}
{fn_submit}

(async () => {{
  const form = {{
    _submitting: false,
    getAttribute: () => '/p/manage-user',
    querySelector: () => ({{ disabled: false }}),
  }};
  nextRes = {{ ok: false, status: 401, type: 'basic', text: async () => '{{"ok":false,"error":"Unauthorized"}}' }};
  await submitUserForm(form);
  nextRes = {{ ok: false, status: 502, type: 'basic', text: async () => '<html><body>' + 'X'.repeat(500) + '</body></html>' }};
  await submitUserForm(form);
  console.log(JSON.stringify({{ alerts, portalSessionExpired }}));
}})();
"""
        proc = subprocess.run(['node', '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout.strip())
        self.assertIn('登录已过期', res['alerts'][0])
        self.assertTrue(res['portalSessionExpired'])
        self.assertLessEqual(len(res['alerts'][1]), 220)

    @unittest.skipUnless(shutil.which('node'), '需要 node 执行前端逻辑验证')
    def test_do_upgrade_keeps_busy_lock_while_waiting_for_reload(self):
        script = _load_script()
        fn_up = _extract_js_function(script, 'doUpgrade')
        js = f"""
const location = {{ pathname: '/p/', reload: () => {{}} }};
const btnUpdateCore = {{ disabled: false, textContent: '升级核心' }};
const btnUpdatePortal = {{ disabled: false, textContent: '升级面板' }};
const btnUpdateAwgEngine = {{ disabled: false, textContent: '升级AWG' }};
const coreVerDisplay = {{ textContent: 'v2.6.0' }};
const updateStatusMsg = {{ textContent: '' }};
let fetchCalls = 0;
async function showConfirm() {{ return true; }}
async function fetch() {{
  fetchCalls++;
  return {{ ok: true, status: 200, json: async () => ({{ ok: true, message: '升级完成' }}) }};
}}
function alert() {{}}
function setTimeout(fn, ms) {{ return 1; }}
{fn_up}

(async () => {{
  await doUpgrade('awg');
  // 已安排 5 秒后自动刷新，此时再次点击升级必须被 _busy 挡住
  await doUpgrade('core');
  console.log(JSON.stringify({{ fetchCalls, busy: !!doUpgrade._busy }}));
}})();
"""
        proc = subprocess.run(['node', '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout.strip())
        self.assertEqual(res['fetchCalls'], 1)
        self.assertTrue(res['busy'])

    def test_ob_test_form_rejects_leading_zero_port(self):
        script = _load_script()
        fn = _extract_js_function(script, 'obTestForm')
        self.assertIn('[1-9]\\d{0,4}', fn)


if __name__ == '__main__':
    unittest.main()
