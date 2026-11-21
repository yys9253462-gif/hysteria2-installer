"""回归测试：portal_ensure_py 事务回滚单文件失败不得中断其余文件恢复；install.sh curl() 跳过目录令牌；fix_cert_chain.sh 备份防撞名并清理残片。"""

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
FIX_CERT = ROOT / 'fix_cert_chain.sh'
BASH = shutil.which('bash')


class PortalBundleRollbackAndCertChainTests(unittest.TestCase):
    def test_portal_ensure_py_rollback_continues_remaining_files_on_single_error(self):
        """发布事务回滚时，即使某个文件恢复抛 OSError，也必须继续恢复其余已替换文件。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        m = re.search(r"cat <<'PYINSTALLBUNDLE'|<<'PYINSTALLBUNDLE'\n(.*?)\nPYINSTALLBUNDLE", src, re.S)
        self.assertIsNotNone(m)
        py_body = m.group(1)
        # 确认回滚循环隔离单文件异常并使用 missing_ok=True
        rb_idx = py_body.index('for f in reversed(written):')
        rb_block = py_body[rb_idx:]
        self.assertIn('missing_ok=True', rb_block, '新建文件回滚未使用 unlink(missing_ok=True)')
        self.assertIn('except OSError', rb_block, '回滚循环未隔离单文件 OSError，单次失败会中断其余文件恢复')

    def test_install_sh_curl_checks_regular_file_before_reading_token(self):
        """install.sh 的 curl() 必须检查 -f 常规文件，防止目录或特殊文件导致读取报错或阻塞。"""
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        fn = re.search(r'^curl\(\) \{.*?^\}', src, re.S | re.M).group(0)
        self.assertIn('[[ -f "$HY2_GITHUB_TOKEN_FILE" && -r "$HY2_GITHUB_TOKEN_FILE" ]]', fn)

    def test_fix_cert_chain_backup_is_private_unique_and_cleans_on_failure(self):
        """fix_cert_chain.sh 备份路径应含进程号防同秒撞名，且在私有掩码下创建并失败清理半成品。"""
        src = FIX_CERT.read_text(encoding='utf-8').replace('\r\n', '\n')
        self.assertNotIn('BK="${CONFIG}.bak.$(date +%Y%m%d%H%M%S)"\n    cp -a "$CONFIG" "$BK" || { err', src)
        self.assertIn('$$', src[src.index('BK='):src.index('已备份原配置')])
        self.assertIn('rm -f "$BK"', src[src.index('BK='):src.index('已备份原配置')])


if __name__ == '__main__':
    unittest.main()
