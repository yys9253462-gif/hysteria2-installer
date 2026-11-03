"""AnyTLS 服务崩溃后订阅里不再下发它（2026-11-04 修）。

_active_anytls_config 只看「已启用 + anytls.json 在」：hy2-anytls 崩溃后订阅照样带着
AnyTLS 节点，手动选它的用户连不上。起真门户进程，PATH 里放一个报 hy2-anytls failed
的假 systemctl，取用户的 clash.yaml。
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


@unittest.skipIf(os.name == 'nt', 'needs a POSIX systemctl stub on PATH')
class SingboxServedOnlyWhenRunningTest(unittest.TestCase):
    def fetch_clash(self, anytls_state):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake = root / 'bin'
            fake.mkdir()
            (fake / 'systemctl').write_text(
                '#!/bin/sh\nif [ "$1" = is-active ] && [ "$2" = hy2-anytls ]; then echo %s; exit 3; fi\n'
                'echo inactive; exit 3\n' % anytls_state, encoding='utf-8')
            (fake / 'systemctl').chmod(0o755)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            (root / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
            portal.prepare(root / 'client_meta.json', port)
            data = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            data['users']['buyer'] = {'password': 'pw-buyer', 'status': 'active',
                                      'expires_at': 4102444800, 'view_nonce': 'n1'}
            data['anytls_config'] = {'enabled': True, 'port': 2096, 'domain': 'hy2.example.com',
                                     'sni': 'hy2.example.com', 'secret': 'a' * 64}
            (root / 'portal.json').write_text(json.dumps(data), encoding='utf-8')
            (root / portal.ANYTLS_CONFIG_NAME).write_text('{"inbounds": []}', encoding='utf-8')
            env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ.get('PATH', ''),
                       HY2_CORE_OPERATION_LOCK=str(root / 'core.lock'))
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
                url = 'http://127.0.0.1:%d/%s/u/buyer/clash.yaml?k=%s' % (port, data['token'], key)
                return urllib.request.urlopen(url, timeout=20).read().decode('utf-8')
            finally:
                proc.terminate()
                proc.wait(timeout=5)

    def test_crashed_anytls_is_left_out(self):
        self.assertNotIn('AnyTLS', self.fetch_clash('failed'))

    def test_running_anytls_is_served(self):
        # 只有 hy2-anytls 报 active；脚本对它也 exit 3，但 _systemd_state 只看输出。
        self.assertIn('AnyTLS', self.fetch_clash('active'))


if __name__ == '__main__':
    unittest.main()
