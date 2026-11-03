"""老 systemd 的机器要在申请证书之前就被拦下（2026-11-04 修）。

门户需要 systemd 247+；旧实现只在 generate_server_config 里查，ACME 证书已经签完
（占 Let's Encrypt 配额）才中止。执行真实的 flow_install，systemctl 报 245，
其余步骤全部打桩并记录调用顺序。
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def fn(name):
    return re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M).group(0)


@unittest.skipUnless(BASH, 'requires bash')
class SystemdCheckBeforeCertTests(unittest.TestCase):
    def test_old_systemd_stops_before_any_certificate_work(self):
        stubs = '\n'.join('%s() { echo CALL %s; }' % (n, n) for n in (
            'check_root', 'check_arch', 'acquire_installer_core_lock', 'install_dependencies',
            'get_public_ip', 'install_binary', 'setup_certificates', 'setup_ports_and_obfs',
            'generate_server_config', 'setup_system_firewall', 'setup_systemd', 'show_client_configs'))
        script = '\n'.join([
            'log_err() { echo "ERR $*"; }', 'log_warn() { :; }', 'log_info() { :; }',
            'HY2_CONFIG=/nonexistent/config.yaml',
            'systemctl() { [[ "$1" == --version ]] && echo "systemd 245 (245.4)"; }',
            stubs, fn('require_systemd_247'), fn('flow_install'),
            'flow_install; echo "RC=$?"'])
        out = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                             encoding='utf-8', timeout=20).stdout
        self.assertIn('RC=1', out)
        self.assertIn('247', out)
        self.assertNotIn('CALL setup_certificates', out, '老 systemd 也走到了申请证书')
        self.assertNotIn('CALL install_dependencies', out)


if __name__ == '__main__':
    unittest.main()
