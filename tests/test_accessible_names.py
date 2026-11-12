"""页面上的输入框 / 文本框 / 下拉框都要有可读名称（2026-11-13 修）。

旧页面不少控件只有占位文字（读屏不念、一输入就消失），几个文本框的 aria-label 直接写的元素 id，
念出来是「hy2-link」「teyir-access-json」这类代码名；客户分享页的直链与订阅框也没有名称。
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
ID_LIKE = re.compile(r'[a-z0-9]+(?:[-_][a-z0-9]+)+')


def unnamed_controls(page):
    """没有可读名称的可见控件，以及 id 式的 aria-label。"""
    page = re.sub(r'<script\b.*?</script>', '', page, flags=re.S)
    labelled_for = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', page))
    wrapped = [m.span() for m in re.finditer(r'<label\b.*?</label>', page, re.S)]
    problems = []
    for m in re.finditer(r'<(input|textarea|select)\b([^>]*)>', page):
        tag, attrs = m.group(1), m.group(2)
        if re.search(r'type="(hidden|submit|button|checkbox)"', attrs) or 'aria-hidden="true"' in attrs:
            continue
        el_id = re.search(r'\bid="([^"]+)"', attrs)
        label = re.search(r'aria-label="([^"]*)"', attrs)
        named = (label or 'aria-labelledby=' in attrs or (el_id and el_id.group(1) in labelled_for)
                 or any(a <= m.start() < b for a, b in wrapped))
        name = el_id.group(1) if el_id else attrs.strip()[:40]
        if not named:
            problems.append('无名称 %s#%s' % (tag, name))
        elif label and ID_LIKE.fullmatch(label.group(1)):
            problems.append('id 式名称 %s#%s=%s' % (tag, name, label.group(1)))
    return problems


class AccessibleNamesTest(unittest.TestCase):
    def test_admin_page(self):
        page = render({'buyer01': {'password': 'pw1', 'status': 'active', 'expires_at': 4102444800,
                                   'created_at': 1}})
        self.assertEqual(unnamed_controls(page), [])

    def test_share_and_login_pages(self):
        share = portal.user_page_html('n.example', 'n.example', 443, 'QUIC', 'bob', {'used_bytes': 0},
                                      'hysteria2://x@n.example:443', 'clash', '{}', '', 'tok', 'k', 8443,
                                      extra_links=[('Reality', 'vless://a'), ('VMess', 'vmess://b')])
        self.assertEqual(unnamed_controls(share), [])
        self.assertEqual(unnamed_controls(portal.login_html('tok', 'err', username='u')), [])

    @unittest.skipUnless(NODE, 'requires node')
    def test_user_connection_modal(self):
        payload = dict(PAYLOAD, extra_links=[{'label': 'Reality', 'uri': 'vless://a'}])
        js = r"""
const mk = () => ({textContent: '', innerHTML: '', classList: {add() {}, remove() {}}, querySelectorAll: () => []});
const uModal = mk(), uModalBody = mk(), uModalTitle = mk(), uModalSub = mk(), uModalClose = mk();
const location = {origin: 'https://h.example.com:8443'};
const btn = {dataset: {uid: 'alice', token: 'tok', key: 'kkk'}, addEventListener(type, fn) { this.onclick = fn; }};
const document = {querySelectorAll: sel => (sel === '.btn-user-connect' ? [btn] : [])};
const fetch = async () => ({status: 200, ok: true, json: async () => (%s)});
%s
btn.onclick().then(() => console.log(uModalBody.innerHTML));
""" % (json.dumps(payload), modal_block(portal.SCRIPT))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(unnamed_controls(run.stdout), [])


if __name__ == '__main__':
    unittest.main()
