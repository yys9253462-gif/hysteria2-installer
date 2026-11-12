"""生成不出二维码时，分享页与用户弹窗说清楚怎么办（2026-11-13 修）。

qrencode 是可选依赖（RHEL 系未开 EPEL 时装不上）。旧实现里分享页留一个空框、下面还写着
「扫描即可直接接入」，管理员的用户弹窗一直显示「二维码生成中...」—— 它永远不会生成。
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_user_modal_singbox import PAYLOAD, modal_block  # noqa: E402

NODE = shutil.which('node')


class SharePageQrTest(unittest.TestCase):
    def page(self, qr):
        return portal.user_page_html('n.example', 'n.example', 443, 'QUIC', 'bob', {'used_bytes': 0},
                                     'hysteria2://x@n.example:443', 'clash', '{}', qr, 'tok', 'k', 8443)

    def test_missing_qr_explains_what_to_do(self):
        self.assertIn('二维码生成失败', self.page(''))
        self.assertIn('请复制节点直链导入', self.page(''))

    def test_real_qr_is_shown_as_is(self):
        page = self.page('<svg id="real-qr"></svg>')
        self.assertIn('<svg id="real-qr"></svg>', page)
        self.assertNotIn('二维码生成失败', page)


@unittest.skipUnless(NODE, 'requires node')
class UserModalQrTest(unittest.TestCase):
    def test_modal_does_not_promise_a_qr_that_never_comes(self):
        js = r"""
const mk = () => ({textContent: '', innerHTML: '', classList: {add() {}, remove() {}}, querySelectorAll: () => []});
const uModal = mk(), uModalBody = mk(), uModalTitle = mk(), uModalSub = mk(), uModalClose = mk();
const location = {origin: 'https://h.example.com:8443'};
const btn = {dataset: {uid: 'alice', token: 'tok', key: 'kkk'}, addEventListener(type, fn) { this.onclick = fn; }};
const document = {querySelectorAll: sel => (sel === '.btn-user-connect' ? [btn] : [])};
const fetch = async () => ({status: 200, ok: true, json: async () => (%s)});
%s
btn.onclick().then(() => console.log(uModalBody.innerHTML));
""" % (json.dumps(dict(PAYLOAD, qr_svg='')), modal_block(portal.SCRIPT))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('二维码生成失败', run.stdout)
        self.assertNotIn('生成中', run.stdout)


if __name__ == '__main__':
    unittest.main()
