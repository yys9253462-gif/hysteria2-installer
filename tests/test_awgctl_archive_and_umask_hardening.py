"""回归测试：awgctl.sh 归档链接成员与反斜杠拦截、首次安装半写回滚清理及 umask 077 私有临时文件创建。"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


class AwgctlArchiveAndUmaskHardeningTests(unittest.TestCase):
    def _fn(self, name: str) -> str:
        m = re.search(rf'^{name}\(\) \{{.*?\n\}}', AWGCTL, re.S | re.M)
        self.assertIsNotNone(m, f'未找到函数 {name}')
        return m.group(0)

    def test_download_binaries_blocks_links_backslashes_and_cleans_partial_install(self):
        """download_binaries 必须用 tar -tvzf 拦截符号/硬链接与反斜杠、拒收符号链接组件并清理首次半写残留。"""
        body = self._fn('download_binaries')
        self.assertIn('tar -tvzf "${tmpd}/awg.tar.gz"', body)
        self.assertIn(r'*\\*', body)
        self.assertIn('[[ ! -f "${tmpd}/${f}" || -L "${tmpd}/${f}" ]]', body)
        self.assertIn('umask 077; mktemp -d "${AWG_DIR}/.binbak.XXXXXX"', body)
        self.assertIn('else\n                rm -f "$f"', body)
        self.assertIn('[[ -f "${tmpd}/VERSION" && ! -L "${tmpd}/VERSION" ]]', body)

    def test_meta_set_and_transaction_snapshot_use_umask_077(self):
        """meta_set 与 awg_transaction_snapshot 创建临时文件与目录必须在 umask 077 下完成。"""
        meta_body = self._fn('meta_set')
        self.assertIn('(umask 077; echo \'{}\' > "$AWG_META_FILE")', meta_body)
        self.assertIn('umask 077; mktemp "${AWG_DIR}/.meta.XXXXXX"', meta_body)

        snap_body = self._fn('awg_transaction_snapshot')
        self.assertIn('umask 077; mktemp -d "${TMPDIR:-/tmp}/hy2-awg-transaction.XXXXXX"', snap_body)


if __name__ == '__main__':
    unittest.main()
