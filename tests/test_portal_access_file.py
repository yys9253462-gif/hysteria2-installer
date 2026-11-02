"""portal-access.json 损坏时管理页仍能打开；IPv6 主机的门户地址要带方括号（2026-11-03）。

* regenerate_page 与首页渲染直接 json.loads(portal-access.json)：文件被截断（磁盘满）
  或写成 [] 时，每次打开管理页都失败，只能手修文件。
* prepare / refresh 拼门户地址与订阅地址时没用 _host_for_url，IPv6 public_ip 拼出
  https://2001:db8::1:8443/...，控制台存下的门户地址解析不了。
"""
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))
import fake_hy2_stats  # noqa: E402
import portal  # noqa: E402
from test_round2_fixes import META  # noqa: E402


class AccessFileHelperTests(unittest.TestCase):
    def test_corrupt_or_missing_access_file_reads_as_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'portal-access.json'
            self.assertEqual(portal.read_access_file(path), {})
            for content in ('{"username": "adm', '[]', 'null', '"x"', '7'):
                with self.subTest(content=content):
                    path.write_text(content, encoding='utf-8')
                    self.assertEqual(portal.read_access_file(path), {})
            path.write_text('{"username": "adm", "password": "pw"}', encoding='utf-8')
            self.assertEqual(portal.read_access_file(path)['username'], 'adm')


class Ipv6PortalUrlTests(unittest.TestCase):
    def test_prepare_writes_bracketed_ipv6_urls(self):
        meta = dict(META, public_ip='2001:db8::10', is_insecure=True, subscription_port=8443)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            (root / 'client_meta.json').write_text(json.dumps(meta), encoding='utf-8')
            portal.prepare(root / 'client_meta.json', port)
            access = json.loads((root / 'portal-access.json').read_text(encoding='utf-8'))
            parsed = urllib.parse.urlsplit(access['url'])
            self.assertEqual(parsed.hostname, '2001:db8::10', access['url'])
            self.assertEqual(parsed.port, 8443)


class CorruptAccessFilePortalTest(unittest.TestCase):
    """起真实门户，把 portal-access.json 写坏后打开管理首页。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        (cls.root / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
        portal.prepare(cls.root / 'client_meta.json', cls.port)
        cls.data = json.loads((cls.root / 'portal.json').read_text(encoding='utf-8'))
        (cls.root / 'portal-access.json').write_text('{"username": "adm', encoding='utf-8')
        cls.stats = fake_hy2_stats.start(cls.root)
        cls.proc = subprocess.Popen(
            [sys.executable, str(ROOT / 'portal.py'), 'serve', str(cls.root / 'portal.json')],
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

    def test_admin_page_still_renders(self):
        import hashlib
        import hmac
        token, secret = self.data['token'], self.data['session_secret']
        iat = str(int(time.time()))
        sig = hmac.new(secret.encode(), f'sess:{token}:{iat}'.encode(), hashlib.sha256).hexdigest()
        req = urllib.request.Request('http://127.0.0.1:%d/%s/' % (self.port, token),
                                     headers={'Cookie': f'hy2_session={token}.{iat}.{sig}'})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, body = r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read().decode('utf-8', 'replace')
        self.assertEqual(status, 200, body[:200])
        self.assertIn('teyir-join-card', body)


if __name__ == '__main__':
    unittest.main()
