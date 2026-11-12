"""「专属连接」与代理详情弹窗的焦点与读屏语义（2026-11-13 修）。

旧实现打开弹窗时焦点留在背后的触发按钮上，读屏与纯键盘用户不知道弹窗已经打开，关掉后焦点也丢了；
两个弹窗没有 dialog 语义，「×」按钮没有可读名称，右上角的提示条读屏不会播报。
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_hash_routing import render  # noqa: E402
from test_user_modal_singbox import PAYLOAD, modal_block  # noqa: E402

NODE = shutil.which('node')


def function_source(src, header):
    start = src.index(header)
    return src[start:src.index('\n}\n', start) + 3]


@unittest.skipUnless(NODE, 'requires node')
class ModalFocusTest(unittest.TestCase):
    def test_focus_moves_to_the_close_button_and_returns(self):
        s = portal.SCRIPT
        js = r"""
const assert = require('assert');
const document = {activeElement: null, querySelectorAll: sel => (sel === '.btn-user-connect' ? [btn] : [])};
const classes = () => { const c = new Set(); return {add: x => c.add(x), remove: x => c.delete(x), contains: x => c.has(x)}; };
const node = id => ({id, textContent: '', innerHTML: '', classList: classes(), querySelectorAll: () => [],
                     focus() { document.activeElement = this; }});
const uModal = node('user-modal'), uModalBody = node('um-body'), uModalTitle = node('um-title'),
      uModalSub = node('um-sub'), uModalClose = node('um-close');
const proxyModal = node('proxy-modal'), pmClose = node('pm-close');
const location = {origin: 'https://h.example.com:8443'};
const btn = {dataset: {uid: 'alice', token: 'tok', key: 'kkk'}, addEventListener(type, fn) { this.onclick = fn; },
             focus() { document.activeElement = this; }};
const fetch = async () => ({status: 200, ok: true, json: async () => (%s)});
%s
%s
%s
(async () => {
  btn.focus();
  await btn.onclick();
  assert.strictEqual(document.activeElement, uModalClose, '打开弹窗后焦点没有进到弹窗里');
  closeUserModal();
  assert.strictEqual(document.activeElement, btn, '关闭弹窗后焦点没有回到触发按钮');
  // 代理详情弹窗：打开时同一套 focusModal，关闭时把焦点还回去。
  btn.focus();
  proxyModal.classList.add('show');
  focusModal(pmClose);
  assert.strictEqual(document.activeElement, pmClose);
  closeProxyModal();
  assert.strictEqual(document.activeElement, btn);
  console.log('OK');
})().catch(e => { console.error(e.message); process.exit(1); });
""" % (json.dumps(PAYLOAD), modal_block(s), function_source(s, 'function closeUserModal()'),
       function_source(s, 'function closeProxyModal()'))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('OK', run.stdout)


class ModalSemanticsTest(unittest.TestCase):
    def test_dialogs_close_buttons_and_toasts_are_announced(self):
        page = render({'buyer01': {'password': 'pw1', 'status': 'active', 'expires_at': 4102444800,
                                   'created_at': 1}})
        ids = set(re.findall(r'\bid="([^"]+)"', page))
        for modal_id in ('user-modal', 'proxy-modal'):
            with self.subTest(modal=modal_id):
                tag = re.search(r'<div[^>]*\bid="%s"[^>]*>' % modal_id, page).group(0)
                self.assertIn('role="dialog"', tag)
                self.assertIn('aria-modal="true"', tag)
                labelled = re.search(r'aria-labelledby="([^"]+)"', tag)
                self.assertIsNotNone(labelled)
                self.assertIn(labelled.group(1), ids)
        for close_id in ('um-close', 'pm-close'):
            with self.subTest(close=close_id):
                tag = re.search(r'<button[^>]*\bid="%s"[^>]*>' % close_id, page).group(0)
                self.assertIn('aria-label="关闭"', tag)
        toast = re.search(r'<div[^>]*\bid="toast-container"[^>]*>', page).group(0)
        self.assertIn('aria-live="polite"', toast)


if __name__ == '__main__':
    unittest.main()
