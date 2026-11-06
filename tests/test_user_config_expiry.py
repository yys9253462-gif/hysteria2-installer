"""GET /<token>/user-config 回给管理员弹窗的到期时间（2026-11-03）。

expires_at 缺失表示永久（AGENTS.md）。旧实现兜底成 0，前端弹窗按 `=== null`
判断永久，于是永久用户显示成 1970-01-01 到期；而 0 在本项目里表示「已过期」。
这里起真实门户进程，从 HTTP 层验证返回值。
"""
import hashlib
import hmac
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))
import fake_hy2_stats  # noqa: E402
import portal  # noqa: E402
from test_round2_fixes import META  # noqa: E402


class UserConfigExpiryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        (cls.root / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
        portal.prepare(cls.root / 'client_meta.json', cls.port)
        data_path = cls.root / 'portal.json'
        cls.data = json.loads(data_path.read_text(encoding='utf-8'))
        now = int(time.time())
        base = {'ip_limit': 0, 'limit_bytes': 0, 'used_bytes': 0, 'status': 'active',
                'created_at': now, 'note': '', 'view_nonce': 'n1'}
        # 永久用户：没有 expires_at 字段（门户启动时从磁盘读入）。
        cls.data['users']['forever'] = dict(base, password='pw-forever-1')
        cls.data['users']['dated'] = dict(base, password='pw-dated-1', expires_at=now + 86400)
        cls.data['users']['odd'] = dict(base, password='pw-odd-1', ip_limit=True, used_bytes='abc')
        cls.data['users']['brokenx'] = 7   # 改坏的条目（2026-11-06：用户详情 / 分享页曾 500）
        data_path.write_text(json.dumps(cls.data), encoding='utf-8')
        cls.stats = fake_hy2_stats.start(cls.root)
        cls.proc = subprocess.Popen(
            [sys.executable, str(ROOT / 'portal.py'), 'serve', str(data_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), .1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            cls.proc.kill()
            raise RuntimeError('门户服务未能启动')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()
        cls.stats.shutdown()
        cls._tmp.cleanup()

    def user_config(self, uid):
        token, secret = self.data['token'], self.data['session_secret']
        iat = str(int(time.time()))
        sig = hmac.new(secret.encode(), f'sess:{token}:{iat}'.encode(), hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            'http://127.0.0.1:%d/%s/user-config?user_id=%s' % (self.port, token, uid),
            headers={'Cookie': f'hy2_session={token}.{iat}.{sig}'})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')

    def test_permanent_user_reports_null_not_expired_sentinel(self):
        status, body = self.user_config('forever')
        self.assertEqual(status, 200, body)
        self.assertIsNone(body['expires_at'])

    def test_dated_user_keeps_timestamp(self):
        status, body = self.user_config('dated')
        self.assertEqual(status, 200, body)
        self.assertEqual(body['expires_at'], self.data['users']['dated']['expires_at'])

    def test_expiry_text_matches_server_rendering(self):
        """弹窗与用户表 / 分享页同一段文本，带服务器时区（2026-11-04 修）。"""
        status, body = self.user_config('dated')
        self.assertEqual(status, 200, body)
        self.assertEqual(body['expires_text'], portal._expiry_text(self.data['users']['dated']['expires_at']))
        self.assertIn('(UTC', body['expires_text'])

    def test_corrupt_user_entry_is_not_found_not_500(self):
        status, _ = self.user_config('brokenx')
        self.assertEqual(status, 404)
        req = urllib.request.Request('http://127.0.0.1:%d/%s/u/brokenx/?k=x' % (self.port, self.data['token']))
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        self.assertNotEqual(code, 500)

    def test_odd_fields_use_display_rules(self):
        """ip_limit=true 显示为不限、坏用量显示 0（2026-11-04 修，与用户表一致）。"""
        status, body = self.user_config('odd')
        self.assertEqual(status, 200, body)
        self.assertEqual(body['ip_limit'], 0)
        self.assertEqual(body['traffic_used'], 0)


if __name__ == '__main__':
    unittest.main()
