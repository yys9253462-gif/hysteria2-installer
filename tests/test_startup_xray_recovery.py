"""门户启动时恢复 Xray：走真实启动流程，且如实记录结果（2026-11-13 修）。

旧实现在 serve() 里内联一段代码：重启停着的 Xray 后不看结果，日志照写「启动时恢复了 xray 服务」；
测试测的却是另一个早已没人调用、行为也落后了的同名函数。这里起真门户进程，PATH 里放假的
systemctl / journalctl，模拟「Xray 停着」与「重启后起不来」，看门户日志怎么写。
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

META = dict(public_ip='192.0.2.1', server_name='hy2.example.com', listen_port=27490,
            auth_password='secret-pass', obfs_password='obfs-secret', is_insecure=False,
            hop_port_range='20000-40000', subscription_port=11690)

FAKE_SYSTEMCTL = '''#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_ROOT/systemctl.log"
case "$1 $2" in
  "restart xray") [ "$XRAY_STARTS" = 1 ] && echo active > "$FAKE_ROOT/xray.state" ;;
  "is-active xray") state=$(cat "$FAKE_ROOT/xray.state" 2>/dev/null || echo inactive)
                    echo "$state"; [ "$state" = active ]; exit $? ;;
  "is-active "*) echo inactive; exit 3 ;;
esac
exit 0
'''
FAKE_JOURNALCTL = '#!/bin/sh\necho "listen tcp :2087: bind: address already in use"\n'


@unittest.skipUnless(os.name == 'posix', '需要 POSIX shell 写的假 systemctl')
class StartupXrayRecoveryTest(unittest.TestCase):
    def start_portal(self, xray_starts):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        bin_dir = root / 'bin'
        bin_dir.mkdir()
        for name, text in (('systemctl', FAKE_SYSTEMCTL), ('journalctl', FAKE_JOURNALCTL)):
            (bin_dir / name).write_text(text, encoding='utf-8')
            (bin_dir / name).chmod(0o755)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        (root / 'meta.json').write_text(json.dumps(META), encoding='utf-8')
        portal.prepare(root / 'meta.json', port)
        data = json.loads((root / 'portal.json').read_text(encoding='utf-8'))
        # clients 与 portal.json 一致：只剩「服务停着」这一个要处理的问题。
        (root / 'xray.json').write_text(json.dumps({'inbounds': [
            {'tag': portal.VMESS_INBOUND_TAG, 'settings': {'clients': portal.vmess_clients(data)}}]}),
            encoding='utf-8')
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
                   FAKE_ROOT=str(root), XRAY_STARTS='1' if xray_starts else '0')
        proc = subprocess.Popen([sys.executable, str(ROOT / 'portal.py'), 'serve', str(root / 'portal.json')],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            # 端口在启动比对之前就已监听；能收到响应才说明启动流程跑完、开始服务了。
            deadline = time.monotonic() + 40
            while True:
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                    conn.request('GET', '/' + data['token'] + '/')
                    conn.getresponse().read()
                    conn.close()
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        self.fail('门户没有开始服务')
                    time.sleep(0.1)
        finally:
            proc.terminate()
            try:
                _, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
        log_path = root / 'systemctl.log'
        calls = log_path.read_text(encoding='utf-8') if log_path.exists() else ''
        return err.decode('utf-8', 'replace'), calls

    def test_a_stopped_xray_is_restarted_and_reported(self):
        log, calls = self.start_portal(xray_starts=True)
        self.assertIn('restart xray', calls)
        self.assertIn('[portal] 启动时恢复了 xray 服务', log)

    def test_an_xray_that_does_not_come_up_is_not_reported_as_recovered(self):
        log, calls = self.start_portal(xray_starts=False)
        self.assertIn('restart xray', calls)
        self.assertNotIn('启动时恢复了 xray 服务', log)
        self.assertIn('启动时恢复 xray 服务失败', log)
        self.assertIn('address already in use', log)


if __name__ == '__main__':
    unittest.main()
