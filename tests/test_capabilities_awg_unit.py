"""capabilities 报 AmneziaWG 状态要查真正的单元 amneziawg-server（2026-11-03 修）。

旧实现查 `amneziawg-go`（那是二进制名，不是 systemd 单元），每台节点都报停止。
起真门户进程，PATH 里放一个只认 amneziawg-server 为 active 的假 systemctl。
"""
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

META = dict(public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
            auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
            hop_port_range='20000-40000', subscription_port=11690)


@unittest.skipIf(os.name == 'nt', 'needs a POSIX systemctl stub on PATH')
class CapabilitiesAwgUnitTest(unittest.TestCase):
    def test_awg_reported_active_when_its_unit_is_active(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake = root / 'bin'
            fake.mkdir()
            (fake / 'systemctl').write_text(
                '#!/bin/sh\n[ "$1" = is-active ] && [ "$2" = amneziawg-server ] && { echo active; exit 0; }\n'
                'echo inactive; exit 3\n', encoding='utf-8')
            (fake / 'systemctl').chmod(0o755)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            (root / 'meta.json').write_text(json.dumps(META), encoding='utf-8')
            portal.prepare(root / 'meta.json', port)
            data = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ.get('PATH', ''))
            proc = subprocess.Popen([sys.executable, portal.__file__, 'serve', str(root / 'portal.json')],
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
                conn.request('GET', '/api/v1/capabilities',
                             headers={'Authorization': 'Bearer ' + data['api_key']})
                resp = conn.getresponse()
                body = json.loads(resp.read())
                self.assertEqual(resp.status, 200, body)
                self.assertIs(body['extras']['amneziawg']['active'], True, body['extras']['amneziawg'])
            finally:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
