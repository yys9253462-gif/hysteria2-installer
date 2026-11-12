"""安装收尾 / `info` 的安全组提示列出门户里已启用的协议与代理端口（2026-11-12 加）。

此前只列 Hy2 自己的端口：在门户里开了 Reality / AnyTLS 等的用户照着放行仍然连不上。
执行真实的 enabled_protocol_ports 与 show_client_configs，jq 用真的。
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')

XRAY = {'inbounds': [{'tag': 'vless-reality-in', 'port': 8443}, {'tag': 'vmess-ws-in', 'port': 2083},
                     {'tag': 'my-own-inbound', 'port': 9999}, 'garbage']}
PORTAL = {'anytls_config': {'enabled': True, 'port': 41234}, 'tuic_config': {'enabled': False, 'port': 42000},
          'proxy_services': [{'port': 30001, 'type': 'socks5'}, 7]}
WANT = ['TCP 8443 VLESS-Reality', 'TCP 2083 VMess', 'TCP 41234 AnyTLS', 'TCP 30001 入站代理（socks5）',
        'UDP 51888 AmneziaWG']


def fn(name):
    m = re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M)
    return m.group(0) if m else ''


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class InfoProtocolPortsTests(unittest.TestCase):
    def run_in_fixture(self, body):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / 'xray.json').write_text(json.dumps(XRAY), encoding='utf-8')
            (t / 'portal.json').write_text(json.dumps(PORTAL), encoding='utf-8')
            (t / 'anytls.json').write_text('{}', encoding='utf-8')
            (t / 'tuic.json').write_text('{}', encoding='utf-8')
            (t / 'awg0.conf').write_text('[Interface]\nPrivateKey = x\nListenPort = 51888\n', encoding='utf-8')
            (t / 'portal-access.json').write_text(json.dumps(
                {'url': 'https://node.example.com:23456/tok/', 'username': 'u', 'password': 'p'}), encoding='utf-8')
            (t / 'client_meta.json').write_text(json.dumps(
                {'listen_port': 14617, 'hop_port_range': '20000-40000', 'cert_type': 'self_signed'}), encoding='utf-8')
            script = '\n'.join(['HY2_DIR=%s' % t, 'HY2_META_FILE=%s/client_meta.json' % t,
                                'AWG_CONFIG=%s/awg0.conf' % t, 'log_err() { echo "ERR $*"; }', 'log_warn() { :; }',
                                fn('enabled_protocol_ports'), fn('show_client_configs'), body])
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30)

    def test_enabled_ports_are_listed_and_others_are_not(self):
        r = self.run_in_fixture('enabled_protocol_ports')
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        self.assertEqual(sorted(lines), sorted(WANT), r.stderr)

    def test_security_group_section_shows_them(self):
        r = self.run_in_fixture('show_client_configs')
        self.assertNotIn('ERR', r.stdout)
        for want in WANT:
            proto, port, label = want.split(' ', 2)
            self.assertRegex(r.stdout, r'%s %s\s+%s' % (proto, port, re.escape(label)))
        self.assertNotIn('9999', r.stdout)
        self.assertNotIn('42000', r.stdout)


if __name__ == '__main__':
    unittest.main()
