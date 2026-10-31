"""第五轮排查修复的回归测试（2026-10-15）。

- sing-box server_ports 每项都是「起:止」区间（单写 "443" 会让 sing-box 拒绝整份配置）
- 新增无鉴权的 /api/health 存活探针
- 面板自更新后起不来会自动回滚
- reality-online 在流量超额停用期间不重启 xray
- Reality / GOST 端口在 ufw / firewalld 上放行与收回
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import portal  # noqa: E402
from test_round2_fixes import PortalServer  # noqa: E402

TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
META = {'public_ip': '203.0.113.10', 'server_name': 'node.example.com', 'listen_port': 443,
        'auth_password': 'pw', 'obfs_password': 'o', 'is_insecure': False,
        'hop_port_range': '20000-40000'}


def parse_sing_box_ports(items):
    """与 sing-quic hysteria.ParsePorts 同一规则：每项必须含冒号。"""
    ports = []
    for item in items:
        if ':' not in item:
            raise ValueError('bad port range: ' + item)
        start, end = item.split(':', 1)
        ports.extend(range(int(start or 0), int(end or 65535) + 1))
    return ports


class SingBoxPortsTest(unittest.TestCase):
    def sing(self, meta):
        sing = portal.artifacts(meta)[-1]
        return json.loads(sing) if isinstance(sing, str) else sing

    def find_hy2(self, sing):
        if isinstance(sing, dict) and sing.get('type') == 'hysteria2':
            return sing
        for value in (sing.values() if isinstance(sing, dict) else sing if isinstance(sing, list) else []):
            found = self.find_hy2(value)
            if found:
                return found
        return None

    def test_every_entry_is_a_range_sing_box_accepts(self):
        outbound = self.find_hy2(self.sing(META))
        self.assertEqual(outbound['server_ports'], ['443:443', '20000:40000'])
        ports = parse_sing_box_ports(outbound['server_ports'])
        self.assertIn(443, ports)
        self.assertIn(20000, ports)
        self.assertIn(40000, ports)

    def test_without_hopping_uses_plain_server_port(self):
        outbound = self.find_hy2(self.sing(dict(META, hop_port_range='')))
        self.assertEqual(outbound['server_port'], 443)
        self.assertNotIn('server_ports', outbound)


class HealthEndpointTest(PortalServer):
    def test_health_needs_no_auth_and_leaks_nothing(self):
        status, body = self.request('/api/health')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'ok': True})

    def test_other_api_routes_still_require_auth(self):
        self.assertEqual(self.request('/api/v1/users/list')[0], 401)


@unittest.skipIf(os.name != 'posix', '需要 POSIX shell 与可执行桩')
class SelfUpdateRollbackTest(unittest.TestCase):
    def run_script(self, healthy):
        td = Path(tempfile.mkdtemp())
        bindir = td / 'bin'
        bindir.mkdir()
        log = td / 'calls.log'
        for name in ('systemctl', 'logger'):
            stub = bindir / name
            stub.write_text('#!/bin/sh\necho "%s $*" >> %s\n' % (name, log))
            stub.chmod(0o755)
        py = bindir / 'python3'
        py.write_text('#!/bin/sh\nexit %d\n' % (0 if healthy else 1))
        py.chmod(0o755)
        dest = td / 'portal.py'
        dest.write_text('new')
        dest.chmod(0o644)
        bak = td / 'portal.py.bak'
        bak.write_text('old')
        bak.chmod(0o600)
        added = td / 'added.py'
        added.write_text('new file')
        script = portal.portal_update_restart_script(1, [(dest, bak)], [added], wait_seconds=2)
        script = script.replace('sleep 1', 'sleep 0')
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ['PATH'])
        subprocess.run(['bash', '-c', script], env=env, timeout=30, check=False)
        return dest.read_text(), added.exists(), log.read_text(), dest.stat().st_mode & 0o777

    def test_unhealthy_update_rolls_back_and_restarts(self):
        content, added_exists, calls, mode = self.run_script(healthy=False)
        self.assertEqual(content, 'old')
        self.assertEqual(mode, 0o600)
        self.assertFalse(added_exists)
        self.assertEqual(calls.count('systemctl restart hysteria-portal'), 2)
        self.assertIn('logger', calls)

    def test_healthy_update_is_kept(self):
        content, added_exists, calls, mode = self.run_script(healthy=True)
        self.assertEqual(content, 'new')
        self.assertEqual(mode, 0o644)
        self.assertTrue(added_exists)
        self.assertEqual(calls.count('systemctl restart hysteria-portal'), 1)


class SelfUpdateScriptShapeTest(unittest.TestCase):
    def test_script_probes_health_and_restores_backups(self):
        script = portal.portal_update_restart_script(
            18080, [(Path('/etc/hysteria/portal.py'), Path('/etc/hysteria/portal.py.bak'))],
            [Path('/etc/hysteria/new.py')])
        self.assertIn('127.0.0.1:18080/api/health', script)
        self.assertIn('portal.py.bak', script)
        self.assertIn('new.py', script)
        self.assertIn('&& exit 0', script)

    def test_update_handler_uses_rollback_script(self):
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        self.assertIn("portal_update_restart_script(data['port'], backups, created)", src)
        self.assertNotIn("['bash', '-c', 'sleep 1; systemctl restart hysteria-portal']", src)


class RealityOnlineSuspensionTest(unittest.TestCase):
    def test_reality_online_checks_suspension_before_restarting_xray(self):
        branch = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "target == 'reality-online'")
        first = ast.unparse(branch.body[0])
        self.assertIn("unit_suspended('xray')", first)
        self.assertIn('409', first)


class FirewallPortTest(unittest.TestCase):
    def call(self, port, open_=True, ufw=True, firewalld=False):
        calls = []

        def run(cmd, **kwargs):
            calls.append(cmd)
            out = 'Status: active\n' if cmd[:2] == ['ufw', 'status'] else ''
            return SimpleNamespace(returncode=0, stdout=out)

        which = {'ufw': '/usr/sbin/ufw' if ufw else None,
                 'firewall-cmd': '/usr/bin/firewall-cmd' if firewalld else None}
        with mock.patch.object(portal.shutil, 'which', side_effect=which.get), \
                mock.patch.object(portal.subprocess, 'run', side_effect=run), \
                mock.patch.object(portal, '_systemd_state', return_value='active' if firewalld else 'inactive'):
            portal.firewall_port(port, 'tcp', open_=open_)
        return calls

    def test_ufw_open_and_close(self):
        self.assertIn(['ufw', 'allow', '8443/tcp'], self.call(8443))
        self.assertIn(['ufw', 'delete', 'allow', '8443/tcp'], self.call(8443, open_=False))

    def test_firewalld_open(self):
        calls = self.call(8443, ufw=False, firewalld=True)
        self.assertIn(['firewall-cmd', '--zone=public', '--add-port=8443/tcp', '--permanent'], calls)

    def test_no_firewall_means_no_calls(self):
        self.assertEqual(self.call(8443, ufw=False, firewalld=False), [])

    def test_invalid_port_is_ignored(self):
        self.assertEqual(self.call('abc'), [])
        self.assertEqual(self.call(0), [])

    def test_firewall_errors_never_propagate(self):
        with mock.patch.object(portal.shutil, 'which', return_value='/usr/sbin/ufw'), \
                mock.patch.object(portal.subprocess, 'run', side_effect=OSError('boom')):
            portal.firewall_port(8443)

    def test_reality_and_proxy_paths_open_ports(self):
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        self.assertIn("firewall_port(new_rcfg.get('port'), 'tcp', open_=True)", src)
        self.assertIn("firewall_port(port, 'tcp', open_=True)", src)
        self.assertIn("firewall_port(item.get('port'), 'tcp', open_=False)", src)


if __name__ == '__main__':
    unittest.main()
