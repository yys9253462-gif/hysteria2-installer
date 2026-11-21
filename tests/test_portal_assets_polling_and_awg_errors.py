"""回归测试：portal_assets.py 网速轮询隐藏页暂停、WARP 重置防连点、AWG 四类操作网络异常捕获提示。"""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

NODE = shutil.which('node')


class PortalAssetsPollingAndAwgErrorsTests(unittest.TestCase):
    def test_traffic_speed_interval_skips_hidden_tab_and_expired_session(self):
        script = portal.SCRIPT
        self.assertIn(
            "setInterval(() => { if (!document.hidden && !portalSessionExpired && panelVisible('users')) pollTrafficSpeed(); }, 2000);",
            script,
            '网速 2 秒轮询未在标签页隐藏或会话过期时暂停',
        )

    def test_warp_reset_button_disables_while_in_flight(self):
        script = portal.SCRIPT
        start = script.index('if (btnResetWarpRules) {')
        end = script.index('\ncheckWarpStatus();', start)
        block = script[start:end]
        self.assertIn('btnResetWarpRules.disabled = true;', block)
        self.assertIn('finally', block)
        self.assertIn('btnResetWarpRules.disabled = false;', block)

    @unittest.skipUnless(NODE, 'requires node')
    def test_awg_buttons_report_network_errors_without_unhandled_rejection(self):
        script = portal.SCRIPT
        for marker in ('if (btnDoInstallAwg) {', 'if (btnAddAwgPeer) {', 'if (btnSwitchAwgLine) {', 'if (btnUpdateAwg) {'):
            start = script.index(marker)
            end = script.index('\n}', start) + 2
            block = script[start:end]
            self.assertIn('catch (', block, f'{marker} 缺少网络异常 catch 处理')
            self.assertNotIn('throw e;', block, f'{marker} 不应重新抛出未处理 rejection')

        # 真跑 node 验证 btnAddAwgPeer 网络异常时关闭预开标签页、弹窗提示且恢复按钮
        start = script.index('if (btnAddAwgPeer) {')
        end = script.index('\n}', start) + 2
        code = script[start:end]
        harness = r'''
const assert = require('assert');
let handler;
const tab = {location: 'about:blank', closed: false, close() { this.closed = true; }};
const alerts = [];
const btnAddAwgPeer = {disabled: false, addEventListener: (ev, fn) => handler = fn};
const awgPeerName = {value: 'peer-neterr'}, awgPeerEndpoint = {value: 'vpn.example:51820'};
const awgCurrentEndpoint = '';
const window = {open: () => tab};
const location = {pathname: '/tok/'};
const alert = msg => alerts.push(msg);
const showToast = () => {};
const loadAwgState = () => {};
const awgPost = async () => { throw new TypeError('无法连接服务器'); };
'''
        checks = r'''
(async () => {
  await handler();
  assert.strictEqual(tab.closed, true, '网络异常时未关闭预开标签页');
  assert.strictEqual(btnAddAwgPeer.disabled, false, '网络异常后未恢复按钮');
  assert(alerts.some(m => m.includes('无法连接服务器')), '网络异常未弹窗提示: ' + JSON.stringify(alerts));
})().catch(e => { console.error(e); process.exitCode = 1; });
'''
        r = subprocess.run([NODE, '-e', harness + code + checks], capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
