"""重选订阅端口时避开托管协议记下的端口（2026-11-04 修）。

协议停着时端口能 bind，旧实现会把它选成订阅端口，之后再启用该协议就撞车。
执行 select_subscription_port 里真实的 python 片段，把随机数固定成先给出托管端口。
"""
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _pick_two_free_ports():
    """挑选两个当前可绑定且避开 20000-40000 与保留端口的高位端口，避免 CI 偶发与系统临时端口撞车。"""
    reserved = {8443, 19898, 19996, 19997, 40000, 56195}
    found = []
    for port in range(14500, 19500):
        if port in reserved:
            continue
        with socket.socket() as s:
            try:
                s.bind(('0.0.0.0', port))
            except OSError:
                continue
        found.append(port)
        if len(found) == 2:
            return found[0], found[1]
    raise RuntimeError('unable to find two free test ports')


class SubPortAvoidsManagedTests(unittest.TestCase):
    def test_saved_protocol_port_is_skipped(self):
        body = re.search(r"HY2_SUB_PORT=\$\(python3 - \"\$HY2_DIR/portal.json\" <<'PYPORT'\n(.*?)\nPYPORT", SRC, re.S).group(1)
        managed_port, free_port = _pick_two_free_ports()
        with tempfile.TemporaryDirectory() as td:
            pj = Path(td) / 'portal.json'
            pj.write_text(json.dumps({'vmess_config': {'port': managed_port, 'enabled': False}}))
            seq = [managed_port - 10000, free_port - 10000]
            prog = 'import secrets\n_s=iter(%r)\nsecrets.randbelow=lambda n: next(_s)\n' % seq + body
            out = subprocess.run([sys.executable, '-c', prog, str(pj)], capture_output=True, text=True, timeout=20)
        self.assertEqual(out.stdout.strip(), str(free_port), out.stderr)


if __name__ == '__main__':
    unittest.main()
