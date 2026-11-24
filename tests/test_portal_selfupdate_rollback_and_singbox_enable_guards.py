"""回归测试：portal.py 面板自更新备份/回滚常规文件及目录刷盘与 AnyTLS/TUIC 启用防线。"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')


class PortalSelfupdateRollbackAndSingboxEnableGuardsTests(unittest.TestCase):
    def test_portal_self_update_checks_regular_files_and_fsyncs_dir_on_rollback(self):
        """面板自更新备份与回滚读盘须校验常规文件与大小上限，且回滚结束后须刷盘 base_dir。"""
        start = SOURCE.index('base_dir = PORTAL_SELF.parent')
        end = SOURCE.index("if not changed:", start)
        block = SOURCE[start:end]

        self.assertIn('S_ISREG(_dst_st.st_mode)', block)
        self.assertIn('bak_path.is_symlink()', block)
        self.assertIn('S_ISREG(_bak_st.st_mode)', block)
        self.assertGreaterEqual(
            block.count("os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)"),
            2,
            '正常替换与异常回滚分支均须对 base_dir 执行 O_DIRECTORY fsync',
        )

    def test_anytls_and_tuic_enable_deep_snapshot_isreg_and_sanitize_secret(self):
        """_apply_anytls_enable 须深拷贝端口快照并校常规文件；_apply_tuic_enable 须清洗含空白/控制字符的旧 secret。"""
        a_start = SOURCE.index('def _apply_anytls_enable(self):')
        a_end = SOURCE.index('def _h_post_manage_anytls(self, prefix):', a_start)
        a_block = SOURCE[a_start:a_end]
        self.assertIn('copy.deepcopy(data.get(k))', a_block)
        self.assertNotIn('_data_now = dict(data)', a_block)
        self.assertIn('S_ISREG(', a_block)

        t_start = SOURCE.index('def _apply_tuic_enable(self):')
        t_end = SOURCE.index('def _h_post_manage_tuic(self, prefix):', t_start)
        t_block = SOURCE[t_start:t_end]
        self.assertIn('ord(c) < 32 or ord(c) == 127', t_block)
        self.assertIn('S_ISREG(', t_block)


if __name__ == '__main__':
    unittest.main()
