"""回归测试：portal_assets.py 弹窗焦点容错、switchSubtab 选择器校验、删除表单防重入、代理协议白名单与 AWG 属性转义守卫。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ASSETS_SRC = (REPO / 'portal_assets.py').read_text(encoding='utf-8')


class PortalAssetsModalFocusSubtabFormProxyAndAwgEscGuardsTests(unittest.TestCase):
    def test_focus_modal_and_restore_modal_focus_guard_focus_exceptions(self):
        """focusModal 与 restoreModalFocus 须包裹 try/catch，防止已移除元素 focus() 抛错阻断关窗。"""
        start = ASSETS_SRC.index('function focusModal(closeBtn)')
        end = ASSETS_SRC.index('function closeProxyModal()', start)
        block = ASSETS_SRC[start:end]
        self.assertIn('try { closeBtn.focus(); } catch (_) {}', block)
        self.assertIn('try { target.focus(); } catch (_) {}', block)

    def test_switch_subtab_validates_identifiers_and_delete_form_guards_reentry(self):
        """switchSubtab 须校验 paneId/subId，删除用户表单须在弹窗前拦截 _submitting/_confirming 重入。"""
        s_start = ASSETS_SRC.index('function switchSubtab(paneId, subId)')
        s_end = ASSETS_SRC.index('function panelVisible(paneId, subId)', s_start)
        s_block = ASSETS_SRC[s_start:s_end]
        self.assertIn("typeof paneId !== 'string' || !/^[a-z0-9_-]+$/i.test(paneId)", s_block)
        self.assertIn("typeof subId !== 'string' || !/^[a-z0-9_-]+$/i.test(subId)", s_block)

        f_start = ASSETS_SRC.index('function bindUserForms()')
        f_end = ASSETS_SRC.index('bindUserForms();', f_start)
        f_block = ASSETS_SRC[f_start:f_end]
        self.assertIn('if (form._submitting || form._confirming) return;', f_block)
        self.assertIn('form._confirming = true;', f_block)
        self.assertIn('form._confirming = false;', f_block)

    def test_proxy_table_uses_whitelisted_scheme_and_awg_peers_escape_encoded_attrs(self):
        """loadProxyServices 须用白名单协议类型拼 URL，renderAwgPeers 须对 data-awg-* 包 obEsc 且防删除确认重入。"""
        p_start = ASSETS_SRC.index('async function loadProxyServices()')
        p_end = ASSETS_SRC.index('function closeUserModal()', p_start)
        p_block = ASSETS_SRC[p_start:p_end]
        self.assertIn("const safeScheme = safeTypeClass || 'socks5';", p_block)
        self.assertIn('`${safeScheme}://', p_block)

        a_start = ASSETS_SRC.index('function renderAwgPeers(peers)')
        a_end = ASSETS_SRC.index('if (btnInstallAwg)', a_start)
        a_block = ASSETS_SRC[a_start:a_end]
        self.assertIn('const safeEnc = obEsc(enc);', a_block)
        self.assertIn('data-awg-conf="\' + safeEnc + \'"', a_block)
        self.assertIn("b.dataset.confirming === '1'", a_block)

    def test_node_syntax_check_passes_for_all_scripts(self):
        """若本机有 node，须对 SCRIPT / LOGIN_SCRIPT / USER_SCRIPT 做真实语法检查。"""
        node = shutil.which('node')
        if not node:
            self.skipTest('node not available')
        import sys
        if str(REPO) not in sys.path:
            sys.path.insert(0, str(REPO))
        import portal_assets
        with tempfile.TemporaryDirectory() as td:
            for name in ('SCRIPT', 'LOGIN_SCRIPT', 'USER_SCRIPT'):
                val = getattr(portal_assets, name, '')
                if val:
                    js_file = Path(td) / f'{name}.js'
                    js_file.write_text(val, encoding='utf-8')
                    res = subprocess.run([node, '--check', str(js_file)], capture_output=True, text=True, timeout=15)
                    self.assertEqual(res.returncode, 0, f'{name} JS 语法错: {res.stderr}')


if __name__ == '__main__':
    unittest.main()
