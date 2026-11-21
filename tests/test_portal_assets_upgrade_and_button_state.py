"""回归测试：portal_assets.py 升级按钮超时恢复、安装 WARP/GOST 按钮文案不被 finally 覆盖及代理类型 CSS 类白名单。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = (ROOT / 'portal_assets.py').read_text(encoding='utf-8').replace('\r\n', '\n')


class PortalAssetsUpgradeAndButtonStateTests(unittest.TestCase):
    def test_do_upgrade_restores_portal_button_when_wait_portal_back_times_out(self):
        """面板升级等待恢复超时（!back）时必须恢复按钮可用并改为重试，不得永久卡死在升级中。"""
        start = ASSETS.index('async function doUpgrade(target) {')
        end = ASSETS.index('if (btnRecheckUpdate) {', start)
        body = ASSETS[start:end]
        self.assertIn("if (back) { location.reload(); return; }", body)
        self.assertIn("if (btn) { btn.disabled = false; btn.textContent = '重试升级'; }", body)

    def test_install_gost_and_warp_do_not_overwrite_refreshed_button_text(self):
        """WARP 与 GOST 安装成功后必须等待状态刷新且不得在 finally 里用旧 origText 覆盖新文案。"""
        warp_start = ASSETS.index('if (btnInstallWarp) {')
        warp_end = ASSETS.index('if (formAddWarpRule) {', warp_start)
        warp_body = ASSETS[warp_start:warp_end]
        self.assertIn('if (!installedOk) btnInstallWarp.textContent = origText;', warp_body)

        gost_start = ASSETS.index('if (btnInstallGost) {')
        gost_end = ASSETS.index('async function loadProxyServices() {', gost_start)
        gost_body = ASSETS[gost_start:gost_end]
        self.assertIn('await loadProxyServices();', gost_body)
        self.assertIn('if (!installedOk) btnInstallGost.textContent = origText;', gost_body)

    def test_load_proxy_services_uses_whitelisted_css_class_for_proxy_type(self):
        """loadProxyServices 渲染 proxy-type 样式类时只接受白名单协议类型，避免空格或异常值注入类名。"""
        start = ASSETS.index('async function loadProxyServices() {')
        end = ASSETS.index('loadProxyServices();', start)
        body = ASSETS[start:end]
        self.assertIn("const safeTypeClass = Object.prototype.hasOwnProperty.call(typeLabel, s.type) ? s.type : '';", body)
        self.assertNotIn('<span class="proxy-type ${obEsc(s.type)}">', body)


if __name__ == '__main__':
    unittest.main()
