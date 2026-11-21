"""回归测试：install.sh 的 install_warp_local_proxy 私钥权限保护、临时日志与 systemd 单元原子落盘。"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


class InstallWarpProxyHardeningTests(unittest.TestCase):
    def _body(self):
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        m = re.search(r'^install_warp_local_proxy\(\) \{\n.*?^\}', src, re.S | re.M)
        self.assertIsNotNone(m, '未找到 install_warp_local_proxy')
        return m.group(0)

    def test_wgcf_private_files_protected_and_no_fixed_tmp_logs(self):
        body = self._body()
        self.assertNotIn('>/tmp/wgcf-register.log', body)
        self.assertNotIn('>/tmp/wgcf-generate.log', body)
        self.assertIn('chmod 600 "$WGCF_ACCT"', body)
        self.assertIn('chmod 600 "$WGCF_CONF"', body)

    def test_wireproxy_and_watchdog_units_written_atomically(self):
        body = self._body()
        self.assertNotIn('cat > /etc/systemd/system/wireproxy.service', body)
        self.assertNotIn('cat > /etc/systemd/system/hy2-warp-watchdog.service', body)
        self.assertNotIn('cat > /etc/systemd/system/hy2-warp-watchdog.timer', body)
        self.assertIn('mktemp "/etc/systemd/system/wireproxy.service.XXXXXX"', body)
        self.assertIn('mktemp "/etc/systemd/system/hy2-warp-watchdog.service.XXXXXX"', body)
        self.assertIn('mktemp "/etc/systemd/system/hy2-warp-watchdog.timer.XXXXXX"', body)


if __name__ == '__main__':
    unittest.main()
