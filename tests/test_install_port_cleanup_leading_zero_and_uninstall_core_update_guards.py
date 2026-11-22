"""回归测试：防火墙端口回收防前导零致 jq 崩溃、卸载域与符号链接防护及核心升级 RETURN 清理陷阱。"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', shutil.which('bash')):
        if cand and os.path.isfile(cand):
            return cand
    return None


BASH = _find_bash()
JQ = shutil.which('jq')


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SRC, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}')
    return m.group(0)


class InstallPortCleanupLeadingZeroAndUninstallCoreUpdateGuardsTests(unittest.TestCase):
    def test_port_cleanup_jq_pnum_rejects_leading_zero_and_fractional_ports(self):
        """close_replaced_ports 与 close_installer_ports 的 jq pnum 必须拒绝前导零字符串与小数，防 jq 崩溃漏保端口。"""
        crp = _extract_fn('close_replaced_ports')
        cip = _extract_fn('close_installer_ports')
        for name, body in (('close_replaced_ports', crp), ('close_installer_ports', cip)):
            self.assertIn('test("^[1-9][0-9]{0,4}$")', body, f'{name} 须拒绝前导零字符串防 jq tonumber 崩溃')
            self.assertIn('floor == .', body, f'{name} 须过滤非整数浮点端口')
        self.assertIn('grep -qxF "$1"', crp)

    def test_uninstall_validates_nginx_domain_and_skips_symlinks(self):
        """uninstall_all 须内联校验 nginx_domain 合法性，且删除 sysctl/bbr 配置前须拒绝符号链接。"""
        body = _extract_fn('uninstall_all')
        self.assertIn('[[ "$nginx_domain" =~ ^([a-z0-9]', body)
        self.assertIn('! -L /etc/sysctl.d/99-hysteria2.conf', body)
        self.assertIn('! -L "$bbr_file"', body)

    def test_flow_update_core_uses_return_trap_for_lock_and_rollback(self):
        """flow_update_core 须注册 RETURN 清理陷阱，防止异常返回泄漏文件描述符与回滚备份。"""
        body = _extract_fn('flow_update_core')
        self.assertIn('RETURN', body)
        self.assertIn('rm -f "$rollback_file"', body)

    @unittest.skipUnless(BASH and JQ, 'requires bash and jq')
    def test_close_replaced_ports_survives_leading_zero_corrupt_port_in_portal_json(self):
        """portal.json 含前导零脏端口 "08443" 时，jq 不得崩溃，仍须保护同文件内其余在用协议端口。"""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / 'portal.json').write_text(json.dumps({
                'reality_config': {'port': '08443'},
                'vmess_config': {'port': 8999},
                'proxy_services': [{'port': 44300.5}],
            }), encoding='utf-8')
            script = '\n'.join([
                f'HY2_DIR="{td_path.as_posix()}"',
                'LISTEN_PORT=51000',
                'HY2_SUB_PORT=52000',
                'log_info() { :; }',
                f'ufw() {{ if [[ "$1" == status ]]; then echo "Status: active"; else echo "UFW $*" >> "{(td_path / "calls").as_posix()}"; fi; }}',
                'systemctl() { return 1; }',
                'command() { if [[ "$1" == -v ]]; then [[ "$2" == ufw ]]; return; fi; builtin command "$@"; }',
                _extract_fn('is_valid_port'),
                _extract_fn('close_replaced_ports'),
                'close_replaced_ports 44300 8999',
            ])
            subprocess.run([BASH, '-s'], input=script, capture_output=True, text=True, encoding='utf-8', timeout=20, check=True)
            calls = (td_path / 'calls').read_text(encoding='utf-8') if (td_path / 'calls').exists() else ''
            self.assertNotIn('8999/tcp', calls, '脏前导零端口导致 jq 崩溃后误删了正在使用的 8999/tcp 端口！')
            self.assertIn('44300/udp', calls)


if __name__ == '__main__':
    unittest.main()
