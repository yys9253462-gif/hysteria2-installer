"""REST API 收到孤立代理项字符串时必须 400，不能把门户的落盘整个卡死（2026-11-03）。

json.loads 接受 "\\ud800"，得到的 str 能通过所有 isinstance 检查；但 save_data
编码 UTF-8 时抛 UnicodeEncodeError（不是 OSError，开户的回滚分支接不住）。
坏记录留在内存里，此后每一次落盘都失败：之后的开户、删除、计量、撤销记录
全都写不进 portal.json，直到门户重启。
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_round2_fixes import PortalServer  # noqa: E402


class LoneSurrogateApiTest(PortalServer):
    def raw_api(self, sub, raw):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            'http://127.0.0.1:%d/api/v1/%s' % (self.port, sub), data=raw,
            headers={'Authorization': 'Bearer ' + self.data['api_key'],
                     'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')

    def on_disk_users(self):
        return set(json.loads((self.root / 'portal.json').read_text(encoding='utf-8'))['users'])

    def test_lone_surrogate_is_rejected_and_later_saves_still_work(self):
        for raw in (b'{"user_id": "sur_pw", "password": "ab\\ud800cd"}',
                    b'{"user_id": "sur_note", "note": "x\\udfffy"}',
                    b'{"user_id": "sur_key", "\\ud800": 1}'):
            with self.subTest(raw=raw):
                status, body = self.raw_api('users/create', raw)
                self.assertEqual(status, 400, body)
        status, body = self.api('users/create', {'user_id': 'after_surrogate', 'password': 'pw-after-1'})
        self.assertEqual(status, 200, body)
        self.assertIn('after_surrogate', self.on_disk_users())
        self.assertFalse({'sur_pw', 'sur_note', 'sur_key'} & self.on_disk_users())

    def test_helper_accepts_normal_unicode(self):
        self.assertTrue(portal._utf8_encodable({'note': '中文备注 😀', 'n': [1, 'a', {'k': 'v'}]}))
        self.assertFalse(portal._utf8_encodable({'note': ['ok', '\ud800']}))


if __name__ == '__main__':
    unittest.main()
