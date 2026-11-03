"""门户收到 SIGTERM 时先把内存状态落盘再退出（2026-11-04 修）。

计量每 60 秒才写一次 portal.json；旧实现收到 SIGTERM 直接退出，最多丢一分钟流量，
关机时 Hy2 / Xray 一起换 epoch，这段流量再也补算不回来。起真门户进程，在内存里
记一笔只在下次保存时才落盘的状态，发 SIGTERM，确认它出现在 portal.json 里。
"""
import json
import os
import signal
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


@unittest.skipIf(os.name == 'nt', 'needs POSIX signals')
class SigtermFlushTest(unittest.TestCase):
    def test_sigterm_saves_state_before_exit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            (root / 'meta.json').write_text(json.dumps(META), encoding='utf-8')
            portal.prepare(root / 'meta.json', port)
            before = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertNotIn('_sigterm_probe', before)
            # sitecustomize 在门户进程里装一个钩子：启动 2 秒后往 data 里写一个只在内存的标记。
            hook = root / 'hook'
            hook.mkdir()
            (hook / 'sitecustomize.py').write_text(
                'import threading, time, gc\n'
                'def _mark():\n'
                '    time.sleep(2)\n'
                '    for o in gc.get_objects():\n'
                '        if isinstance(o, dict) and "token" in o and "users" in o and "api_key" in o:\n'
                '            o["_sigterm_probe"] = 1\n'
                'threading.Thread(target=_mark, daemon=True).start()\n', encoding='utf-8')
            env = dict(os.environ, PYTHONPATH=str(hook), HY2_CORE_OPERATION_LOCK=str(root / 'core.lock'))
            proc = subprocess.Popen([sys.executable, portal.__file__, 'serve', str(root / 'portal.json')],
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                time.sleep(4)
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
            after = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
            self.assertEqual(after.get('_sigterm_probe'), 1, 'SIGTERM 时内存状态没有落盘')


if __name__ == '__main__':
    unittest.main()
