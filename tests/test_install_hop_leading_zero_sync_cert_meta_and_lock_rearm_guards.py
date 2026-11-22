import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / 'install.sh'


def _bash_exe():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('bash')


def _extract_fn(src, name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


class InstallHopLeadingZeroSyncCertMetaAndLockRearmGuardTests(unittest.TestCase):
    def setUp(self):
        self.src = INSTALL_SH.read_text(encoding='utf-8').replace('\r\n', '\n')

    def test_setup_iptables_port_hopping_rejects_leading_zero_ports_and_cleans_tmp(self):
        fn = _extract_fn(self.src, 'setup_iptables_port_hopping')
        self.assertIn('^[1-9][0-9]{0,4}$', fn)
        self.assertIn('trap - RETURN', fn)
        bash = _bash_exe()
        if not bash:
            self.skipTest('缺少 bash 环境')
        script = 'log_err() { :; }\n' + fn + '\nsetup_iptables_port_hopping 08443 20000 40000 && echo OK || echo BAD'
        proc = subprocess.run([bash, '-c', script], capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.stdout.strip(), 'BAD')

    def test_sync_cert_meta_rejects_empty_der_sha256_uses_multiline_cn_and_checks_object(self):
        fn = _extract_fn(self.src, 'sync_cert_meta')
        self.assertIn('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', fn)
        self.assertIn('-nameopt multiline', fn)
        self.assertIn('type=="object"', fn)
        self.assertIn('trap - RETURN', fn)

    def test_generate_server_config_cleans_cfg_tmp_and_guards_toggle_warp_symlink(self):
        fn = _extract_fn(self.src, 'generate_server_config')
        self.assertIn('trap - RETURN', fn)
        self.assertIn('[[ ! -L "$HY2_DIR/toggle_warp.sh" ]]', fn)

    def test_flow_install_and_reconfigure_rearm_lock_trap_after_generate_server_config(self):
        for name in ('flow_install', 'flow_reconfigure'):
            fn = _extract_fn(self.src, name)
            pos = fn.index('generate_server_config')
            end = fn.index('setup_system_firewall', pos)
            tail = fn[pos:end]
            self.assertIn('trap "$_lock_trap" RETURN', tail, f'{name} 在 generate_server_config 后未重挂锁释放陷阱')


if __name__ == '__main__':
    unittest.main()
