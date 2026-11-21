"""回归测试：门户与安装脚本双端 WARP 安装的版本格式校验、tar 链接/反斜杠拦截、随机暂存、密钥非空校验与看门狗原子落盘。"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8').replace('\r\n', '\n')
INSTALL_SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


class WarpInstallerDualHardeningTests(unittest.TestCase):
    def test_portal_install_warp_hardens_atomic_write_tar_tags_and_staging(self):
        start = PORTAL_SRC.index('def _h_post_install_warp(self, prefix):')
        end = PORTAL_SRC.index('def do_HEAD(self):', start)
        body = PORTAL_SRC[start:end]
        self.assertIn('tmp=$(umask 077; mktemp "${dst}.XXXXXX")', body)
        self.assertIn('tar -tvzf - <"$2"', body)
        self.assertIn(r'*\\*', body)
        self.assertIn('^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$', body)
        self.assertIn('^v?[0-9A-Za-z][0-9A-Za-z._-]{0,63}$', body)
        self.assertIn('mktemp "${WGCF_BIN}.new.XXXXXX"', body)
        self.assertIn('mktemp "${WP_BIN}.new.XXXXXX"', body)
        self.assertNotIn('"${WGCF_BIN}.new"', body)
        self.assertNotIn('"${WP_BIN}.new"', body)

    def test_install_sh_warp_hardens_tags_staging_keys_and_watchdog_atomic_write(self):
        m = re.search(r'^install_warp_local_proxy\(\) \{\n.*?^\}', INSTALL_SRC, re.S | re.M)
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertIn('^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$', body)
        self.assertIn('^v?[0-9A-Za-z][0-9A-Za-z._-]{0,63}$', body)
        self.assertIn('mktemp "${WGCF_BIN}.new.XXXXXX"', body)
        self.assertIn('mktemp "${WP_BIN}.new.XXXXXX"', body)
        self.assertIn('if [[ -z "$WG_PRIV" || -z "$WG_PUB" || -z "$WG_EP" ]]; then', body)
        self.assertNotIn('cat > /usr/local/bin/hy2-warp-watchdog.sh', body)
        self.assertIn('mktemp "/usr/local/bin/hy2-warp-watchdog.sh.XXXXXX"', body)


if __name__ == '__main__':
    unittest.main()
