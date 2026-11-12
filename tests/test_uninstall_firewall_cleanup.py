"""卸载时收回本工具放行过的 ufw / firewalld 端口（2026-11-12 修）。

此前只有「改端口」会收回旧端口：卸载后 UDP 主端口、跳跃区间、TCP 订阅端口与各协议 / 代理端口
一直开着。执行真实的 close_installer_ports，ufw / firewall-cmd 打桩记录调用，jq 用真的。
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

META = {'listen_port': 14617, 'subscription_port': 23456, 'hop_port_range': '20000-40000'}
PORTAL = {'reality_config': {'port': 443}, 'vmess_config': {'port': 8443}, 'anytls_config': {'port': 41234},
          'tuic_config': {'port': 42000}, 'proxy_services': [{'port': 30001}, {'port': 80}]}


def fn(name):
    m = re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M)
    return m.group(0) if m else ''


@unittest.skipUnless(BASH and shutil.which('jq'), 'requires bash and jq')
class UninstallFirewallCleanupTests(unittest.TestCase):
    def run_close(self, with_proxies='1', ufw_active=True, firewalld_active=True):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / 'client_meta.json').write_text(json.dumps(META), encoding='utf-8')
            (t / 'portal.json').write_text(json.dumps(PORTAL), encoding='utf-8')
            script = '\n'.join([
                'set -eo pipefail',
                'HY2_DIR=%s' % t, 'HY2_META_FILE=%s/client_meta.json' % t, 'log_info() { :; }',
                'ufw() { if [[ "$1" == status ]]; then echo "Status: %s"; else echo "ufw $*" >> %s/calls; fi; }'
                % ('active' if ufw_active else 'inactive', t),
                'firewall-cmd() { echo "firewall-cmd $*" >> %s/calls; }' % t,
                'systemctl() { [[ "$1 $2" == "is-active firewalld" ]] && return %d; return 0; }'
                % (0 if firewalld_active else 3),
                fn('is_valid_port'), fn('close_installer_ports'),
                'close_installer_ports %s' % with_proxies, 'echo RC=$?',
            ])
            r = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30)
            calls = (t / 'calls').read_text() if (t / 'calls').exists() else ''
        self.assertIn('RC=0', r.stdout, r.stderr)
        return calls

    def test_ports_opened_by_the_installer_and_portal_are_closed(self):
        calls = self.run_close()
        for rule in ('14617/udp', '20000:40000/udp', '23456/tcp', '8443/tcp', '41234/tcp', '42000/udp', '30001/tcp'):
            self.assertIn('ufw delete allow ' + rule, calls)
        for rule in ('14617/udp', '20000-40000/udp', '23456/tcp', '8443/tcp', '41234/tcp', '42000/udp', '30001/tcp'):
            self.assertIn('firewall-cmd --remove-port=%s --permanent' % rule, calls)
        self.assertIn('firewall-cmd --reload', calls)

    def test_web_ports_are_left_alone(self):
        calls = self.run_close()
        for rule in ('443/tcp', '80/tcp'):
            self.assertNotIn('allow ' + rule, calls)
            self.assertNotIn('--remove-port=' + rule, calls)

    def test_foreign_gost_keeps_its_proxy_ports(self):
        calls = self.run_close(with_proxies='0')
        self.assertNotIn('30001/tcp', calls)
        self.assertIn('ufw delete allow 23456/tcp', calls)

    def test_nothing_happens_without_an_active_firewall_manager(self):
        self.assertEqual(self.run_close(ufw_active=False, firewalld_active=False), '')

    def test_uninstall_closes_ports_before_the_config_directory_is_removed(self):
        body = fn('uninstall_all')
        self.assertIn('close_installer_ports', body)
        self.assertLess(body.index('close_installer_ports'), body.index('清理二进制与配置目录'))


if __name__ == '__main__':
    unittest.main()
