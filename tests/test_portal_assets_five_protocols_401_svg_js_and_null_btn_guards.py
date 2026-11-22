"""回归测试：portal_assets.py 五大协议状态查询与切换按钮的 401 会话过期处理、qr_svg 拦截 javascript: URI 及切换按钮判空守卫。"""

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')


def _load_script() -> str:
    ns = {}
    exec(compile((ROOT / 'portal_assets.py').read_text(encoding='utf-8'), 'portal_assets.py', 'exec'), ns)
    return ns['SCRIPT']


class TestPortalAssetsFiveProtocols401SvgJsAndNullBtnGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = _load_script()

    def test_five_protocol_status_functions_handle_401_block_js_uri_and_guard_null_btn(self):
        """五大协议 check*Status 遇 401 须置位 portalSessionExpired、qr_svg 须拦 javascript:、并判空 toggle 按钮。"""
        s = self.script
        specs = (
            ('checkRealityStatus', 'async function protocolSwitchAction(', 'btnToggleReality'),
            ('checkVmessStatus', 'if (btnToggleVmess) {\n', 'btnToggleVmess'),
            ('checkVlessencStatus', 'if (btnToggleVlessenc) {\n', 'btnToggleVlessenc'),
            ('checkAnytlsStatus', 'if (btnToggleAnytls) {\n', 'btnToggleAnytls'),
            ('checkTuicStatus', 'if (btnToggleTuic) {\n', 'btnToggleTuic'),
        )
        for fn_name, end_marker, btn_var in specs:
            start = s.index(f'async function {fn_name}()')
            end = s.index(end_marker, start)
            block = s[start:end]
            with self.subTest(fn=fn_name):
                self.assertIn('res.status === 401', block, f'{fn_name} 必须识别 401 登录过期')
                self.assertIn('portalSessionExpired = true', block, f'{fn_name} 遇 401 须置位 portalSessionExpired')
                self.assertIn('javascript\\s*:', block, f'{fn_name} 的 qr_svg 校验须拦截 javascript: 链接')
                self.assertIn(f'if ({btn_var}) {btn_var}.textContent =', block,
                              f'{fn_name} 更新开关按钮文案前须判空 {btn_var}')

    def test_five_protocol_toggle_and_reset_buttons_handle_401(self):
        """五大协议切换按钮与重置 Reality 密钥按钮遇 401 须置位 portalSessionExpired 并中文提示。"""
        s = self.script
        blocks = (
            ('btnToggleReality', 'if (btnToggleReality) {\n  btnToggleReality.addEventListener', 'if (btnResetRealityKeys)'),
            ('btnResetRealityKeys', 'if (btnResetRealityKeys) {\n  btnResetRealityKeys.addEventListener', 'function copyWithFeedback('),
            ('btnToggleVmess', 'if (btnToggleVmess) {\n  btnToggleVmess.addEventListener', 'if (btnCopyVmessUri)'),
            ('btnToggleVlessenc', 'if (btnToggleVlessenc) {\n  btnToggleVlessenc.addEventListener', 'if (btnCopyVlessencUri)'),
            ('btnToggleAnytls', 'if (btnToggleAnytls) {\n  btnToggleAnytls.addEventListener', 'if (btnCopyAnytlsUri)'),
            ('btnToggleTuic', 'if (btnToggleTuic) {\n  btnToggleTuic.addEventListener', 'if (btnCopyTuicUri)'),
        )
        for label, start_m, end_m in blocks:
            start = s.index(start_m)
            end = s.index(end_m, start)
            block = s[start:end]
            with self.subTest(btn=label):
                self.assertIn('res.status === 401', block, f'{label} 遇 401 须给出登录过期中文提示')
                self.assertIn('portalSessionExpired = true', block)

    @unittest.skipUnless(NODE, '需要 node 验证 JS 语法')
    def test_script_syntax_valid_in_node(self):
        """修改后的前端 SCRIPT 必须通过 Node.js 完整语法解析。"""
        probe = 'new Function(' + repr(self.script) + '); console.log("SYNTAX_OK");\n'
        r = subprocess.run([NODE, '-'], input=probe, capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('SYNTAX_OK', r.stdout)


if __name__ == '__main__':
    unittest.main()
