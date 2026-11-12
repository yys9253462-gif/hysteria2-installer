"""用户「专属连接」弹窗与客户分享页一样给出 sing-box 订阅（2026-11-13 加）。

user-config 接口一直回着 sing_box，旧弹窗只用了 Clash 那份：用 sing-box / Hiddify 的客户，
管理员只能另开分享页去找。截取弹窗点击处理那一段在 node 里执行，点一下按钮看弹窗内容。
"""
import html
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')
PAYLOAD = {'ok': True, 'uri': 'hysteria2://x@h:1/', 'clash': 'proxies: []', 'sing_box': '{"outbounds": []}',
           'qr_svg': '', 'expires_text': '永久有效', 'traffic_used': 0, 'traffic_limit': 0, 'ip_limit': 0,
           'status_text': None, 'note': ''}


def modal_block(src):
    start = src.index('let userModalSeq = 0;')
    loop = src.index("document.querySelectorAll('.btn-user-connect')", start)
    return src[src.index('function obEsc('):src.index('\n}\n', src.index('function obEsc(')) + 3] \
        + src[start:src.index('\n});\n', loop) + 5]


@unittest.skipUnless(NODE, 'requires node')
class UserModalSingBoxTest(unittest.TestCase):
    def open_modal(self):
        js = r"""
const mk = () => ({textContent: '', innerHTML: '', classList: {add() {}, remove() {}}, querySelectorAll: () => []});
const uModal = mk(), uModalBody = mk(), uModalTitle = mk(), uModalSub = mk();
const location = {origin: 'https://h.example.com:8443'};
const btn = {dataset: {uid: 'alice', token: 'tok', key: 'kkk'}, addEventListener(type, fn) { this.onclick = fn; }};
const document = {querySelectorAll: sel => (sel === '.btn-user-connect' ? [btn] : [])};
const fetch = async () => ({status: 200, ok: true, json: async () => (%s)});
%s
btn.onclick().then(() => console.log(uModalBody.innerHTML));
""" % (json.dumps(PAYLOAD), modal_block(portal.SCRIPT))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout

    def test_modal_offers_the_sing_box_subscription(self):
        body = self.open_modal()
        sub = re.search(r'<input[^>]*id="um-sing-sub"[^>]*value="([^"]*)"', body)
        self.assertIsNotNone(sub, '弹窗里没有 sing-box 订阅链接')
        self.assertEqual(html.unescape(sub.group(1)), 'https://h.example.com:8443/tok/u/alice/sing-box.json?k=kkk')
        self.assertIn('href="/tok/u/alice/sing-box.json?k=kkk"', html.unescape(body))
        text = re.search(r'<textarea id="um-sing"[^>]*>([^<]*)</textarea>', body)
        self.assertEqual(html.unescape(text.group(1)), PAYLOAD['sing_box'])


if __name__ == '__main__':
    unittest.main()
