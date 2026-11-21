"""回归测试：install.sh 的 install_gost 初始配置、自检脚本、systemd 单元改为原子落盘且归属标记在 umask 077 下创建。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


class InstallGostAtomicWritesTests(unittest.TestCase):
    def _body(self):
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        start = src.index('install_gost() {')
        end = src.index('\n}\n', src.index('GOST 所有权标记写入失败', start)) + 3
        return src[start:end]

    def test_gost_config_selfcheck_and_unit_use_mktemp_atomic_replace(self):
        body = self._body()
        self.assertNotIn('cat > "$GOST_CONFIG"', body)
        self.assertNotIn('cat > /usr/local/lib/hy2-gost-selfcheck', body)
        self.assertIn('mktemp "${GOST_CONFIG}.XXXXXX"', body)
        self.assertIn('mktemp "/usr/local/lib/hy2-gost-selfcheck.XXXXXX"', body)
        self.assertIn('chmod 600 "$GOST_CERT_DIR/key.pem"', body)
        self.assertIn('(umask 077; : > "$HY2_DIR/.hy2-gost-owned"', body)


if __name__ == '__main__':
    unittest.main()
