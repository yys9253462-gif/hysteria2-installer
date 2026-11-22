"""回归测试：portal_assets.py 确认弹窗焦点异常容错、WARP轮询防堆积、高危按钮确认重入、出站探活防连点与数组脏元素过滤。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ASSETS_SRC = (REPO / 'portal_assets.py').read_text(encoding='utf-8')


class PortalAssetsConfirmFocusWarpPollProbeReentryAndTypesGuardsTests(unittest.TestCase):
    def test_show_confirm_guards_focus_errors_before_resolve(self):
        """showConfirm 恢复焦点必须在 try/catch 中执行，避免 focus() 抛异常导致 Promise 永久挂起。"""
        start = ASSETS_SRC.index('function showConfirm(options = {})')
        end = ASSETS_SRC.index('async function submitUserForm', start)
        block = ASSETS_SRC[start:end]
        self.assertIn('try { (options.isDanger ? cancelBtn : okBtn).focus(); } catch (_) {}', block)
        self.assertIn('try { if (previousFocus && typeof previousFocus.focus === \'function\') previousFocus.focus(); } catch (_) {}', block)

    def test_warp_status_interval_skips_when_poll_pending(self):
        """checkWarpStatus 须维护自足在途状态 checkWarpStatus._pending，且 10s 定时器在请求未返回时跳过，避免弱网叠发请求。"""
        self.assertIn('checkWarpStatus._pending = (checkWarpStatus._pending || 0) + 1;', ASSETS_SRC)
        self.assertIn('checkWarpStatus._pending = Math.max(0, (checkWarpStatus._pending || 1) - 1);', ASSETS_SRC)
        self.assertIn('!checkWarpStatus._pending && panelVisible(\'proxies\', \'warp\')', ASSETS_SRC)

    def test_high_risk_confirm_handlers_and_outbound_probe_have_reentry_locks(self):
        """重置规则/密钥、切换更新AWG与出站探活按钮均须具备防连点重入保护。"""
        for marker in (
            'btnResetWarpRules._confirming',
            'btnResetRealityKeys._confirming',
            'btnSwitchAwgLine._confirming',
            'btnUpdateAwg._confirming',
            'if (test.disabled) return;',
        ):
            self.assertIn(marker, ASSETS_SRC, f'缺少防重入保护: {marker}')

    def test_load_outbounds_filters_non_object_entries_and_wait_core_checks_session_early(self):
        """loadOutbounds 须过滤非对象脏条目，waitForCoreUpgrade 进循环前须先检查 portalSessionExpired。"""
        start = ASSETS_SRC.index('async function loadOutbounds()')
        end = ASSETS_SRC.index('async function probeOutbound', start)
        lb = ASSETS_SRC[start:end]
        self.assertIn('.filter(o => o && typeof o === \'object\')', lb)
        self.assertIn('.filter(r => r && typeof r === \'object\')', lb)
        self.assertIn('.filter(b => b && typeof b === \'object\')', lb)

        w_start = ASSETS_SRC.index('async function waitForCoreUpgrade()')
        w_end = ASSETS_SRC.index('async function doUpgrade(target)', w_start)
        wb = ASSETS_SRC[w_start:w_end]
        self.assertLess(
            wb.index('if (portalSessionExpired)'),
            wb.index('while (Date.now() < deadline)'),
        )

    def test_node_syntax_check_on_portal_assets_scripts(self):
        """若本机存在 node，须对 portal_assets.py 全部前端脚本常量做真实语法检查。"""
        node = shutil.which('node')
        if not node:
            self.skipTest('node not available')
        import sys
        if str(REPO) not in sys.path:
            sys.path.insert(0, str(REPO))
        import portal_assets
        with tempfile.TemporaryDirectory() as td:
            for name in ('MAIN_SCRIPT', 'LOGIN_SCRIPT'):
                val = getattr(portal_assets, name, '')
                if val:
                    js_file = Path(td) / f'{name}.js'
                    js_file.write_text(val, encoding='utf-8')
                    res = subprocess.run([node, '--check', str(js_file)], capture_output=True, text=True, timeout=15)
                    self.assertEqual(res.returncode, 0, f'{name} JS 语法错: {res.stderr}')


if __name__ == '__main__':
    unittest.main()
