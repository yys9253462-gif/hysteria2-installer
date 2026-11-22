"""回归测试：portal_assets.py 的 WARP/BBR/升级/代理 401 停轮询与提示、防重入、非 JSON 容错及 host 字符串校验。"""

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


class TestPortalAssetsWarpBbrUpgradeProxy401AndReentryGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = _load_script()

    def test_warp_status_and_actions_set_session_expired_on_401_and_guard_reentry(self):
        """checkWarpStatus 遇 401 必须置位 portalSessionExpired；WARP 三个操作按钮须防重入与容错非 JSON。"""
        s = self.script
        ws_start = s.index('async function checkWarpStatus()')
        ws_end = s.index('if (btnToggleWarp)', ws_start)
        ws_block = s[ws_start:ws_end]
        self.assertIn('res.status === 401', ws_block, 'checkWarpStatus 遇 401 必须识别并停轮询')
        self.assertIn('portalSessionExpired = true', ws_block)

        tw_start = ws_end
        tw_end = s.index('if (btnInstallWarp)', tw_start)
        tw_block = s[tw_start:tw_end]
        self.assertIn('if (btnToggleWarp.disabled) return;', tw_block)
        self.assertIn('.json().catch(() => null)', tw_block, 'btnToggleWarp 必须容错非 JSON 502/401 响应')
        self.assertIn('res.status === 401', tw_block)

        iw_start = tw_end
        iw_end = s.index('if (formAddWarpRule)', iw_start)
        iw_block = s[iw_start:iw_end]
        self.assertIn('if (btnInstallWarp.disabled) return;', iw_block)
        self.assertIn('if (!confirmed || btnInstallWarp.disabled) return;', iw_block)
        self.assertIn('.json().catch(() => null)', iw_block, 'btnInstallWarp 必须容错非 JSON 响应')
        self.assertIn('res.status === 401', iw_block)

        rw_start = s.index('if (btnResetWarpRules)')
        rw_end = s.index('checkWarpStatus();', rw_start)
        rw_block = s[rw_start:rw_end]
        self.assertIn('if (btnResetWarpRules.disabled) return;', rw_block)
        self.assertIn('if (!confirmed || btnResetWarpRules.disabled) return;', rw_block)
        self.assertIn('res.status === 401', rw_block)

    def test_bbr_set_button_and_upgrade_and_proxy_guards(self):
        """set-bbr 须防重入与处理 401；checkVersions/waitForCoreUpgrade/doUpgrade/loadProxyServices 须处理 401，host 须校验字符串。"""
        s = self.script

        bbr_start = s.index("title: '开启 ' + label + ' 加速引擎'")
        bbr_before = s[max(0, bbr_start - 450):bbr_start]
        bbr_after = s[bbr_start:bbr_start + 1300]
        self.assertIn('if (btn.disabled) return;', bbr_before)
        self.assertIn('if (!confirmed || btn.disabled) return;', bbr_after)
        self.assertIn('res.status === 401', bbr_after)

        cv_start = s.index('async function checkVersions(')
        cv_end = s.index('async function waitForCoreUpgrade()', cv_start)
        self.assertIn('res.status === 401', s[cv_start:cv_end])
        self.assertIn('portalSessionExpired = true', s[cv_start:cv_end])

        wu_start = cv_end
        wu_end = s.index('async function doUpgrade(', wu_start)
        self.assertIn('portalSessionExpired = true', s[wu_start:wu_end])

        du_start = wu_end
        du_end = s.index('if (btnRecheckUpdate)', du_start)
        du_block = s[du_start:du_end]
        self.assertIn('res.status === 401', du_block)
        portal_start = du_block.index("if (target === 'portal')")
        portal_end = du_block.index("if (btn) { btn.disabled = false; btn.textContent = '重试升级'; }", portal_start)
        self.assertIn('reloading = true;', du_block[portal_start:portal_end])

        lp_start = s.index('async function loadProxyServices()')
        lp_end = s.index('loadProxyServices();', lp_start)
        lp_block = s[lp_start:lp_end]
        self.assertIn('res.status === 401', lp_block)
        self.assertIn("typeof json.host === 'string'", lp_block)

    @unittest.skipUnless(NODE, '需要 node 验证 JS 语法')
    def test_script_syntax_valid_in_node(self):
        """修改后的前端 SCRIPT 必须通过 Node.js 完整语法解析。"""
        probe = 'new Function(' + repr(self.script) + '); console.log("SYNTAX_OK");\n'
        r = subprocess.run([NODE, '-'], input=probe, capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('SYNTAX_OK', r.stdout)


if __name__ == '__main__':
    unittest.main()
