"""门户启动时发现 xray.json 的 clients 与 portal.json 不一致，要按 data 重写（2026-11-03 修）。

旧实现只 `systemctl restart xray`：Xray 重读的还是同一份旧文件。门户在 portal.json
已保存、xray.json 未写时崩溃，新开 / 续费的用户就一直连不上 Reality / VMess，
直到碰巧有别的账号变更。起真门户进程，PATH 里放假的 systemctl 与 xray。
"""
import json
import os
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


@unittest.skipIf(os.name == 'nt', 'needs POSIX stubs on PATH')
class StartupXrayResyncTest(unittest.TestCase):
    def test_stale_clients_are_rewritten_on_start(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake = root / 'bin'
            fake.mkdir()
            log = root / 'calls.log'
            (fake / 'systemctl').write_text(
                '#!/bin/sh\necho "$*" >> "%s"\n'
                'case "$1" in is-active) echo active; exit 0;; show) echo 0123456789abcdef0123456789abcdef; exit 0;; esac\n'
                'exit 0\n' % log, encoding='utf-8')
            (fake / 'xray').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            for f in fake.iterdir():
                f.chmod(0o755)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            (root / 'meta.json').write_text(json.dumps(META), encoding='utf-8')
            portal.prepare(root / 'meta.json', port)
            data = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            data['users']['buyer'] = {'password': 'pw-buyer', 'status': 'active',
                                      'expires_at': 4102444800}
            (root / 'portal.json').write_text(json.dumps(data), encoding='utf-8')
            # xray.json 停在「buyer 开户之前」：只有占位 client。
            xray = {'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'protocol': 'vless', 'port': 8444,
                                  'settings': {'clients': [{'id': 'old', 'email': 'placeholder',
                                                            'flow': 'xtls-rprx-vision'}]}}]}
            (root / 'xray.json').write_text(json.dumps(xray), encoding='utf-8')
            (root / 'usage-meter-config.json').write_text(
                json.dumps({'reality': {'binary': str(fake / 'xray')}}), encoding='utf-8')
            env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ.get('PATH', ''),
                       HY2_CORE_OPERATION_LOCK=str(root / 'core.lock'))
            # stderr 写文件而不是 PIPE：没人读的管道写满后门户会卡在写日志上；失败时附上它便于排查。
            stderr_path = root / 'portal.stderr'
            with open(stderr_path, 'wb') as stderr_file:
                proc = subprocess.Popen([sys.executable, portal.__file__, 'serve', str(root / 'portal.json')],
                                        env=env, stdout=subprocess.DEVNULL, stderr=stderr_file)
                try:
                    deadline = time.time() + 20
                    emails = []
                    while time.time() < deadline:
                        cfg = json.loads((root / 'xray.json').read_text(encoding='utf-8'))
                        emails = [c.get('email') for c in cfg['inbounds'][0]['settings']['clients']]
                        if 'buyer' in emails:
                            break
                        time.sleep(0.2)
                finally:
                    proc.terminate()
                    proc.wait(timeout=5)
            self.assertIn('buyer', emails, '启动时没有按 portal.json 重写 xray clients；门户 stderr：\n'
                          + stderr_path.read_text(encoding='utf-8', errors='replace')[-2000:])


if __name__ == '__main__':
    unittest.main()
