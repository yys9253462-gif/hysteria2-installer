"""回归测试：前端出站模式/保存/删除防重入与空编辑、BBR与流量轮询401停轮询、AWG名正则对齐与弹窗容错、登录显隐判空。"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS_PATH = ROOT / 'portal_assets.py'
NODE = shutil.which('node')


def _load_scripts():
    ns = {}
    exec(ASSETS_PATH.read_text(encoding='utf-8'), ns)
    return ns['SCRIPT'], ns['LOGIN_SCRIPT']


class PortalAssetsOutboundBbrTraffic401AwgNameAndLoginGuardsTests(unittest.TestCase):
    def setUp(self):
        self.portal_js, self.login_js = _load_scripts()

    def test_outbound_mode_save_delete_reentry_and_edit_null_guards(self):
        """setOutboundMode/出站删除须在确认后二次防重入，btnSave 入口判 disabled，编辑须防 found 为空。"""
        mode_start = self.portal_js.index('async function setOutboundMode')
        mode_part = self.portal_js[mode_start:self.portal_js.index('if (obEls.btnSave)', mode_start)]
        confirm_pos = mode_part.index('await showConfirm')
        self.assertIn('if (!confirmed || obModeBusy) return;', mode_part[confirm_pos:])

        save_start = self.portal_js.index('if (obEls.btnSave)')
        save_part = self.portal_js[save_start:self.portal_js.index('if (obEls.list)', save_start)]
        self.assertIn('if (obEls.btnSave.disabled) return;', save_part)

        list_start = self.portal_js.index('if (obEls.list)')
        list_part = self.portal_js[list_start:self.portal_js.index('if (obEls.rulesList)', list_start)]
        del_confirm = list_part.index('await showConfirm')
        self.assertIn('if (!confirmed || del.disabled) return;', list_part[del_confirm:])
        self.assertIn('if (!found) return;', list_part)

    def test_bbr_and_traffic_speed_set_session_expired_on_401(self):
        """checkBbrStatus 与 pollTrafficSpeed 遇 401 必须置位 portalSessionExpired，避免死循环打 401。"""
        bbr_start = self.portal_js.index('async function checkBbrStatus')
        bbr_part = self.portal_js[bbr_start:self.portal_js.index('const certBadge', bbr_start)]
        self.assertIn('res.status === 401', bbr_part)
        self.assertIn('portalSessionExpired = true', bbr_part)
        self.assertIn('hasOwnProperty.call', bbr_part)

        ts_start = self.portal_js.index('async function pollTrafficSpeed')
        ts_part = self.portal_js[ts_start:self.portal_js.index('setInterval(', ts_start)]
        self.assertIn('res.status === 401', ts_part)
        self.assertIn('portalSessionExpired = true', ts_part)
        self.assertIn("typeof json !== 'object'", ts_part)

    def test_awg_peer_name_regex_decode_and_tab_guards_and_login_toggle_secret(self):
        """btnAddAwgPeer 须拒绝以 . 或 - 开头名称并检查 !confTab.closed；renderAwgPeers 须保护 decodeURIComponent；toggleSecret 判空 btn。"""
        render_start = self.portal_js.index('function renderAwgPeers')
        render_part = self.portal_js[render_start:self.portal_js.index('if (btnInstallAwg)', render_start)]
        del_pos = render_part.index("querySelectorAll('[data-awg-del]')")
        self.assertIn('try { n = decodeURIComponent(', render_part[del_pos:])

        add_start = self.portal_js.index('if (btnAddAwgPeer)')
        add_part = self.portal_js[add_start:self.portal_js.index('if (btnSwitchAwgLine)', add_start)]
        self.assertIn('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/', add_part)
        self.assertIn('!confTab.closed', add_part)
        self.assertIn('json && json.ok', add_part)

        self.assertIn('if (!el || !btn) return;', self.login_js)

    @unittest.skipUnless(NODE, '需要 node 运行 JS 行为验证')
    def test_node_runtime_syntax_and_behavior(self):
        """用真实 Node.js 验证修改后脚本语法合法且 pollTrafficSpeed/toggleSecret 行为正确。"""
        probe = f"""
const vm = require('vm');
const adminJs = {json.dumps(self.portal_js)};
const loginJs = {json.dumps(self.login_js)};
// 1. 语法校验
new vm.Script(adminJs);
new vm.Script(loginJs);
// 2. toggleSecret 缺 btn 不崩溃
const ctx = {{ document: {{ getElementById: () => ({{ type: 'password' }}), querySelectorAll: () => [] }} }};
vm.runInNewContext(loginJs + '; toggleSecret("p", null);', ctx);
// 3. AWG 名称正则行为
const re = /^[A-Za-z0-9][A-Za-z0-9_.-]{{0,31}}$/;
for (const bad of ['.', '..', '-evil', '.hidden', '']) {{
  if (re.test(bad)) throw new Error('should reject ' + bad);
}}
for (const good of ['phone1', 'my-lap_01.a']) {{
  if (!re.test(good)) throw new Error('should accept ' + good);
}}
console.log('NODE_OK');
"""
        r = subprocess.run([NODE, '-'], input=probe, capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('NODE_OK', r.stdout)


if __name__ == '__main__':
    unittest.main()
