"""回归测试：前端确认弹窗防并发重入、AWG 字段类型守卫、用户弹窗 query 编码与代理凭据字符串校验。"""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal_assets  # noqa: E402


class PortalAssetsConfirmReentryAwgTypesAndUserModalGuardsTests(unittest.TestCase):
    def test_reboot_upgrade_and_proxy_delete_guard_confirm_reentry(self):
        """btnRebootServer、doUpgrade 与 [data-proxy-del] 在 showConfirm 弹窗等待期间须防连点重入。"""
        js = portal_assets.SCRIPT
        self.assertIn('btnRebootServer._confirming', js)
        self.assertIn('doUpgrade._confirming', js)
        self.assertIn("btn.dataset.confirming", js)

    def test_load_awg_state_validates_endpoint_line_and_peers_array(self):
        """loadAwgState 须校验 endpoint/line 为字符串、peers 为数组，防止非数组崩溃或渲染 [object Object]。"""
        js = portal_assets.SCRIPT
        start = js.index('async function loadAwgState()')
        end = js.index('function fmtAwgCreated(', start)
        fn = js[start:end]
        self.assertIn("typeof json.endpoint === 'string'", fn)
        self.assertIn("typeof json.line === 'string'", fn)
        self.assertIn('Array.isArray(json.peers) ? json.peers : []', fn)

    def test_user_modal_encodes_user_key_guards_null_dom_and_non_string_note(self):
        """用户连接弹窗须对 userKey 做 encodeURIComponent、判空 uModalTitle/uModalSub 并校验 note 为字符串。"""
        js = portal_assets.SCRIPT
        start = js.index("document.querySelectorAll('.btn-user-connect')")
        end = js.index('/* ==================== AmneziaWG', start)
        block = js[start:end]
        self.assertIn("encodeURIComponent(userKey || '')", block)
        self.assertIn("if (uModalTitle) uModalTitle.textContent", block)
        self.assertIn("if (uModalSub) uModalSub.textContent", block)
        self.assertIn("typeof json.note === 'string' && json.note", block)

    def test_load_proxy_services_validates_string_credentials_and_js_syntax(self):
        """loadProxyServices 须校验代理账号密码为字符串，且全部内嵌脚本通过 node --check。"""
        js = portal_assets.SCRIPT
        start = js.index('async function loadProxyServices()')
        end = js.index('let userModalSeq = 0;', start)
        block = js[start:end]
        self.assertIn("typeof s.username === 'string' ? s.username : ''", block)
        self.assertIn("typeof s.password === 'string' ? s.password : ''", block)

        node = shutil.which('node')
        if node:
            for name, code in (
                ('SCRIPT', portal_assets.SCRIPT),
                ('LOGIN_SCRIPT', portal_assets.LOGIN_SCRIPT),
                ('USER_SCRIPT', portal_assets.USER_SCRIPT),
            ):
                res = subprocess.run([node, '--check'], input=code.encode('utf-8'), capture_output=True, timeout=15)
                self.assertEqual(res.returncode, 0, f'{name} 语法检查失败: {res.stderr.decode("utf-8", errors="replace")}')


if __name__ == '__main__':
    unittest.main()
