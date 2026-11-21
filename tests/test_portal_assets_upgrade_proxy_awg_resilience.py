import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ASSETS = (REPO / 'portal_assets.py').read_text(encoding='utf-8')


def _extract_script():
    ns = {}
    exec(ASSETS, ns)
    return ns['SCRIPT']


@unittest.skipUnless(shutil.which('node'), '需要 node 执行前端脚本沙箱测试')
class TestPortalAssetsUpgradeProxyAwgResilience(unittest.TestCase):
    def _run_node(self, code: str):
        proc = subprocess.run(
            ['node', '-e', code],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f'Node 执行失败:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}')
        return proc.stdout

    def test_do_upgrade_handles_non_json_502_and_updates_status_on_error(self):
        """doUpgrade 遇到 502 HTML 页与网络异常时必须提示状态码并更新状态文案、恢复按钮。"""
        script = _extract_script()
        start = script.index('async function doUpgrade(target) {')
        end = script.index('if (btnRecheckUpdate) {', start)
        fn_src = script[start:end]

        js = f"""
const alerts = [];
globalThis.alert = (m) => alerts.push(String(m));
globalThis.location = {{ pathname: '/tok/', reload: () => {{}} }};
const btnUpdateCore = {{ disabled: false, textContent: '升级核心' }};
const btnUpdatePortal = {{ disabled: false, textContent: '升级面板' }};
const btnUpdateAwgEngine = {{ disabled: false, textContent: '升级引擎' }};
const coreVerDisplay = {{ textContent: 'v2.6.0' }};
const updateStatusMsg = {{ textContent: '' }};
globalThis.showConfirm = async () => true;
globalThis.waitForCoreUpgrade = async () => ({{}});
globalThis.waitPortalBack = async () => true;

let callCount = 0;
globalThis.fetch = async () => {{
  callCount++;
  if (callCount === 1) {{
    return {{ ok: false, status: 502, json: async () => {{ throw new SyntaxError('Unexpected token <'); }} }};
  }}
  throw new Error('network down');
}};

{fn_src}

(async () => {{
  await doUpgrade('core');
  if (btnUpdateCore.disabled) throw new Error('502 后按钮未恢复');
  if (!alerts[0] || !alerts[0].includes('502')) throw new Error('502 错误未含状态码: ' + alerts[0]);
  if (!updateStatusMsg.textContent.includes('502')) throw new Error('状态文案未反映 502: ' + updateStatusMsg.textContent);

  await doUpgrade('core');
  if (!updateStatusMsg.textContent.includes('network down')) {{
    throw new Error('异常分支未更新状态文案: ' + updateStatusMsg.textContent);
  }}
  console.log('DO_UPGRADE_OK');
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
        out = self._run_node(js)
        self.assertIn('DO_UPGRADE_OK', out)

    def test_show_proxy_result_brackets_ipv6_and_guards_non_svg_qr(self):
        """showProxyResult 拼接 IPv6 回退链接必须加方括号，且拒绝把非 SVG 文本注入二维码框。"""
        script = _extract_script()
        start = script.index('function showProxyResult(data) {')
        end = script.index('// 绑定秒级一键生成按钮', start)
        fn_src = script[start:end]

        js = f"""
const resPTypeBadge = {{ textContent: '', className: '' }};
const resPHost = {{ textContent: '' }};
const resPPort = {{ textContent: '' }};
const resPUser = {{ textContent: '' }};
const resPPass = {{ textContent: '' }};
const resPUrl = {{ value: '' }};
const resPFmt = {{ value: '' }};
const resPQr = {{ innerHTML: '' }};
const btnCopyPUrl = {{}};
const btnCopyPFmt = {{}};
const pmClose = {{ focus: () => {{}} }};
const proxyModal = {{ classList: {{ add: () => {{}} }} }};
let curProxyServerHost = '2001:db8::1';
globalThis.document = {{ querySelectorAll: () => [] }};
globalThis.focusModal = () => {{}};
globalThis.copyWithFeedback = () => {{}};

{fn_src}

showProxyResult({{ type: 'socks5', host: '2001:db8::1', port: 12345, username: 'u', password: 'p', qr: '<img src=x onerror=alert(1)>' }});
if (!resPUrl.value.includes('@[2001:db8::1]:12345')) {{
  throw new Error('IPv6 代理地址未加方括号: ' + resPUrl.value);
}}
if (resPQr.innerHTML.includes('<img')) {{
  throw new Error('非 SVG 字符串被直接写入二维码容器: ' + resPQr.innerHTML);
}}
console.log('PROXY_RESULT_OK');
"""
        out = self._run_node(js)
        self.assertIn('PROXY_RESULT_OK', out)

    def test_awg_post_handles_non_json_502_and_render_awg_peers_skips_null(self):
        """awgPost 遇到 502 HTML 页应返回含 HTTP 状态码的错误对象，renderAwgPeers 须跳过空元素。"""
        script = _extract_script()
        awg_post_src = script[script.index('function awgPost('):script.index('function setAwgBadge(')]
        render_start = script.index('function fmtAwgCreated(')
        render_end = script.index('if (btnInstallAwg) {', render_start)
        render_src = script[render_start:render_end]

        js = f"""
globalThis.location = {{ pathname: '/tok/' }};
globalThis.fetch = async () => ({{
  ok: false,
  status: 502,
  json: async () => {{ throw new SyntaxError('Unexpected token <'); }}
}});
const obEsc = s => String(s == null ? '' : s);
const awgPeerTbody = {{ innerHTML: '', querySelectorAll: () => [] }};

{awg_post_src}
{render_src}

(async () => {{
  const res = await awgPost('manage-amneziawg', {{ action: 'update' }});
  if (res.ok !== false || !String(res.error || '').includes('502')) {{
    throw new Error('awgPost 未在 502 非 JSON 响应中保留状态码: ' + JSON.stringify(res));
  }}
  renderAwgPeers([null, {{ name: 'phone', address: '10.8.0.2/32', created_at: '' }}]);
  if (!awgPeerTbody.innerHTML.includes('phone')) {{
    throw new Error('renderAwgPeers 未能跳过 null 并正常渲染合法客户端');
  }}
  console.log('AWG_OK');
}})().catch(e => {{ console.error(e); process.exit(1); }});
"""
        out = self._run_node(js)
        self.assertIn('AWG_OK', out)

    def test_user_connect_modal_handles_non_json_502_and_proxy_buttons_guard_502(self):
        """专属连接弹窗、快速生成代理与删除代理遇到非 JSON 502 均应展示 HTTP 状态码而非语法异常。"""
        script = _extract_script()
        user_connect_src = script[script.index("document.querySelectorAll('.btn-user-connect')"):script.index('/* ==================== AmneziaWG')]
        self.assertIn('res.json().catch(() => null)', user_connect_src)
        self.assertIn("typeof json.qr_svg === 'string' && json.qr_svg.includes('<svg')", user_connect_src)

        quick_proxy_src = script[script.index("document.querySelectorAll('.btn-quick-proxy')"):script.index('async function loadProxyServices()')]
        self.assertIn('res.json().catch(() => null)', quick_proxy_src)
        self.assertIn('if (btn.disabled) return;', quick_proxy_src)


if __name__ == '__main__':
    unittest.main()
