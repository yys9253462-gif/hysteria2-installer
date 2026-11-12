"""用户「专属连接」弹窗与客户分享页一样列出其它已启用协议的直链（2026-11-13 加）。

UDP 不通的客户要靠 Reality / VMess 等 TCP 协议兜底；旧弹窗只有 Hy2 一条直链，管理员只能另开
分享页去找。截取弹窗点击处理那一段在 node 里执行。
"""
import html
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
from test_user_modal_singbox import modal_block  # noqa: E402

NODE = shutil.which('node')
REALITY = 'vless://u@1.2.3.4:443?security=reality&a=1#Reality-<alice>'
PAYLOAD = {'ok': True, 'uri': 'hysteria2://x@h:1/', 'clash': 'proxies: []', 'sing_box': '{}', 'qr_svg': '',
           'expires_text': '永久有效', 'traffic_used': 0, 'traffic_limit': 0, 'ip_limit': 0, 'status_text': None,
           'note': '', 'extra_links': [{'label': 'Reality', 'uri': REALITY}, {'label': 'VMess', 'uri': ''}]}


@unittest.skipUnless(NODE, 'requires node')
class UserModalExtraLinksTest(unittest.TestCase):
    def test_enabled_protocol_links_are_listed_and_escaped(self):
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
        body = run.stdout
        text = re.search(r'<textarea id="um-extra-0"[^>]*>([^<]*)</textarea>', body)
        self.assertIsNotNone(text, '弹窗里没有 Reality 直链')
        self.assertEqual(html.unescape(text.group(1)), REALITY)
        self.assertIn('data-modal-copy="um-extra-0"', body)
        self.assertNotIn('um-extra-1', body, '空直链不应渲染')
        self.assertNotIn('<alice>', body)


if __name__ == '__main__':
    unittest.main()
