"""回归测试：portal_assets.py 全量剩余接口 401 会话过期置位与代理/用户弹窗 SVG XSS（事件处理器/foreignObject/javascript:）防护。"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

import portal_assets

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')


def _slice_block(src: str, start_marker: str, end_marker: str) -> str:
    i = src.index(start_marker)
    j = src.index(end_marker, i)
    return src[i:j]


class TestPortalAssetsRemaining401AndProxyUserSvgXssGuards(unittest.TestCase):
    def test_remaining_endpoints_set_portal_session_expired_on_401(self):
        """WARP 增删、证书状态、重启、核心安装卸载、代理操作与 AWG 状态遇到 401 均须置位 portalSessionExpired。"""
        s = portal_assets.SCRIPT
        blocks = [
            ('addWarpRule', _slice_block(s, 'async function addWarpRule(domain)', 'async function delWarpRule(domain)')),
            ('delWarpRule', _slice_block(s, 'async function delWarpRule(domain)', 'function markStatusUnknown(')),
            ('checkCertStatus', _slice_block(s, 'async function checkCertStatus()', 'document.querySelectorAll(\'.btn-apply-bbr\')')),
            ('btnRebootServer', _slice_block(s, 'if (btnRebootServer)', '(function initUserTable()')),
            ('installCore', _slice_block(s, 'async function installCore(core, btn)', 'async function uninstallCore(core, btn)')),
            ('uninstallCore', _slice_block(s, 'async function uninstallCore(core, btn)', 'function gotoTarget(target)')),
            ('btn-quick-proxy', _slice_block(s, "document.querySelectorAll('.btn-quick-proxy')", 'if (btnInstallGost)')),
            ('btnInstallGost', _slice_block(s, 'if (btnInstallGost)', 'async function loadProxyServices()')),
            ('data-proxy-del', _slice_block(s, "proxyTbody.querySelectorAll('[data-proxy-del]')", 'function closeUserModal()')),
            ('loadAwgState', _slice_block(s, 'async function loadAwgState()', 'function fmtAwgCreated(')),
        ]
        for name, body in blocks:
            with self.subTest(block=name):
                self.assertIn('res.status === 401', body, f'{name} 缺少 401 状态判断')
                self.assertIn('portalSessionExpired = true', body, f'{name} 遇 401 未置位 portalSessionExpired')

    def test_proxy_and_user_modal_svg_guards_block_xss_vectors(self):
        """showProxyResult 与用户连接弹窗的二维码渲染必须拦截 foreignObject、on* 事件与 javascript: URI。"""
        s = portal_assets.SCRIPT
        proxy_body = _slice_block(s, 'function showProxyResult(data)', '// 绑定秒级一键生成按钮')
        user_body = _slice_block(s, "document.querySelectorAll('.btn-user-connect')", 'function awgPost(')
        for name, body in (('showProxyResult', proxy_body), ('userModal', user_body)):
            with self.subTest(block=name):
                self.assertIn('<foreignObject', body, f'{name} 未拦截 <foreignObject>')
                self.assertIn(r'\bon[a-z]+\s*=', body, f'{name} 未拦截 on* 内联事件属性')
                self.assertIn(r'javascript\s*:', body, f'{name} 未拦截 javascript: 伪协议')

    @unittest.skipUnless(NODE, 'requires node')
    def test_show_proxy_result_blocks_onload_and_javascript_svg_at_runtime(self):
        """Node 实跑 showProxyResult：恶意 onload / javascript: SVG 必须回退提示文本，合法 SVG 正常渲染。"""
        s = portal_assets.SCRIPT
        fn_src = _slice_block(s, 'function showProxyResult(data)', '// 绑定秒级一键生成按钮')
        js = f'''
let curProxyServerHost = '1.2.3.4';
const proxyModal = {{ classList: {{ add() {{}} }} }};
const resPTypeBadge = {{}}, resPHost = {{}}, resPPort = {{}}, resPUser = {{}}, resPPass = {{}}, resPUrl = {{}}, resPFmt = {{}};
const resPQr = {{ innerHTML: '' }};
const btnCopyPUrl = null, btnCopyPFmt = null, pmClose = null;
function focusModal() {{}}
const document = {{ querySelectorAll() {{ return []; }}, getElementById() {{ return null; }} }};
{fn_src}

showProxyResult({{ type: 'socks5', port: 1080, username: 'u', password: 'p', qr: '<svg onload="alert(1)"></svg>' }});
if (resPQr.innerHTML.includes('onload')) {{ console.error('LEAK_ONLOAD'); process.exit(1); }}

showProxyResult({{ type: 'socks5', port: 1080, username: 'u', password: 'p', qr: '<svg><a href="javascript:alert(1)">x</a></svg>' }});
if (resPQr.innerHTML.includes('javascript:')) {{ console.error('LEAK_JS'); process.exit(2); }}

showProxyResult({{ type: 'socks5', port: 1080, username: 'u', password: 'p', qr: '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>' }});
if (!resPQr.innerHTML.includes('<rect')) {{ console.error('BLOCKED_VALID'); process.exit(3); }}
console.log('ALL_OK');
'''
        proc = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('ALL_OK', proc.stdout)


if __name__ == '__main__':
    unittest.main()
