"""用户订阅带 subscription-userinfo 头（2026-11-12 加）。

Clash Verge / Stash / Shadowrocket / sing-box 读这个头在订阅列表显示已用、总量与到期；
此前没有它，买家只能去问卖家还剩多少流量。函数级断言取值规则，再起真门户取两种订阅。
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

META = dict(public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
            auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
            hop_port_range='20000-40000', subscription_port=11690)


class SubscriptionUserinfoValueTests(unittest.TestCase):
    def test_used_quota_and_expiry(self):
        self.assertEqual(portal.subscription_userinfo(
            {'used_bytes': 1234, 'limit_bytes': 10737418240, 'expires_at': 4102444800}),
            'upload=0; download=1234; total=10737418240; expire=4102444800')

    def test_unlimited_and_permanent_are_zero(self):
        self.assertEqual(portal.subscription_userinfo({'used_bytes': 5, 'limit_bytes': 0, 'expires_at': None}),
                         'upload=0; download=5; total=0; expire=0')
        self.assertEqual(portal.subscription_userinfo({}), 'upload=0; download=0; total=0; expire=0')

    def test_corrupt_values_never_reach_the_header(self):
        for bad in (True, -5, 'abc', float('inf'), [1]):
            with self.subTest(bad=bad):
                self.assertEqual(portal.subscription_userinfo(
                    {'used_bytes': bad, 'limit_bytes': bad, 'expires_at': bad}),
                    'upload=0; download=0; total=0; expire=0')


@unittest.skipIf(os.name == 'nt', 'portal serve needs POSIX')
class SubscriptionUserinfoHeaderTests(unittest.TestCase):
    def test_both_user_subscriptions_carry_the_header(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            (root / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
            portal.prepare(root / 'client_meta.json', port)
            data = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            data['users']['buyer'] = {'password': 'pw-buyer', 'status': 'active', 'view_nonce': 'n1',
                                      'used_bytes': 1234, 'limit_bytes': 10737418240, 'expires_at': 4102444800}
            (root / 'portal.json').write_text(json.dumps(data), encoding='utf-8')
            env = dict(os.environ, HY2_CORE_OPERATION_LOCK=str(root / 'core.lock'))
            proc = subprocess.Popen([sys.executable, portal.__file__, 'serve', str(root / 'portal.json')],
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                key = portal.user_view_key(data['session_secret'], 'buyer', 'n1')
                headers = {}
                for name in ('clash.yaml', 'sing-box.json'):
                    url = 'http://127.0.0.1:%d/%s/u/buyer/%s?k=%s' % (port, data['token'], name, key)
                    with urllib.request.urlopen(url, timeout=20) as r:
                        headers[name] = (r.headers.get('subscription-userinfo'),
                                         r.headers.get('profile-update-interval'),
                                         r.headers.get('Content-Disposition'))
            finally:
                proc.terminate()
                proc.wait(timeout=5)
        want = 'upload=0; download=1234; total=10737418240; expire=4102444800'
        self.assertEqual(headers, {
            'clash.yaml': (want, '24', 'attachment; filename="hy2.example.com-buyer.yaml"'),
            'sing-box.json': (want, '24', 'attachment; filename="hy2.example.com-buyer.json"')})


class SubscriptionProfileHeaderTests(unittest.TestCase):
    def test_file_name_keeps_only_safe_characters(self):
        headers = dict(portal.subscription_profile_headers(
            {'server_name': 'hy2.example.com', 'is_insecure': True, 'public_ip': '2001:db8::1'}, 'buyer', 'yaml'))
        self.assertEqual(headers['profile-update-interval'], '24')
        disposition = headers['Content-Disposition']
        name = disposition.split('filename="', 1)[1].rstrip('"')
        self.assertRegex(name, r'^[A-Za-z0-9._-]+\.yaml$')
        self.assertNotIn('\r', disposition)
        self.assertNotIn('\n', disposition)


if __name__ == '__main__':
    unittest.main()
