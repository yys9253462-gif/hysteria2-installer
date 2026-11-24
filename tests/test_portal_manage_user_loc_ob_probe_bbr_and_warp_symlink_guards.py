"""回归测试：portal.py manage-user 跳转头防注入、出站探活参数与并发限流、BBR 控制字符与常规文件校验、WARP 脚本前置符号链接拦截。"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')


class PortalManageUserLocObProbeBbrAndWarpSymlinkGuardsTests(unittest.TestCase):
    def test_manage_user_sanitizes_redirect_location_and_uses_previous_had_user(self):
        """_h_post_manage_user 的 302 Location 须过滤控制字符，且同步失败回滚须依据 previous_had_user。"""
        start = SOURCE.index('def _h_post_manage_user(self, prefix):')
        end = SOURCE.index('def _h_post_login(self, prefix):', start)
        block = SOURCE[start:end]

        self.assertIn("safe_loc = ''.join(ch for ch in str(prefix) if ord(ch) >= 32 and ord(ch) != 127)", block)
        self.assertIn("self.send_header('Location', (safe_loc or '/') + '#users')", block)
        self.assertIn('if not previous_had_user:', block)

    def test_ob_probe_validates_addr_bounds_ctrl_chars_and_bounds_concurrency(self):
        """_ob_probe 须拒绝超长或含控制字符的 addr，并通过有界非阻塞信号量防止探活耗尽门户线程槽。"""
        start = SOURCE.index('def _ob_probe(self):')
        end = SOURCE.index('def _ob_manage(self):', start)
        block = SOURCE[start:end]

        self.assertIn('len(addr) > 512', block)
        self.assertIn('ord(ch) < 32 or ord(ch) == 127', block)
        self.assertIn('_ob_probe_sem', block)
        self.assertIn('429', block)

    def test_bbr_status_uses_isreg_and_sanitizes_control_chars(self):
        """_h_get_bbr_status 须以 stat.S_ISREG 校验 99-bbr.conf 并过滤 sysctl 输出中的控制字符。"""
        start = SOURCE.index('def _h_get_bbr_status(self, subpath):')
        end = SOURCE.index('def _ob_list(self):', start)
        block = SOURCE[start:end]

        self.assertIn('S_ISREG(c_st.st_mode)', block)
        self.assertIn("''.join(ch for ch in", block)

    def test_install_warp_script_rejects_symlinks_before_ownership_probe(self):
        """_h_post_install_warp 内嵌脚本须在归属检查 grep 前先拒绝符号链接资产，防止跟随链接读盘或覆写。"""
        start = SOURCE.index('def _h_post_install_warp(self, prefix):')
        end = SOURCE.index('def do_HEAD(self):', start)
        block = SOURCE[start:end]

        guard = '[ -L "$WARP_OWNED_MARKER" ] || [ -L "$WP_BIN" ] || [ -L /etc/systemd/system/wireproxy.service ] || [ -L "$WP_CFG" ]'
        self.assertIn(guard, block)
        self.assertLess(
            block.index(guard),
            block.index('if [ ! -f "$WARP_OWNED_MARKER" ]; then'),
        )


if __name__ == '__main__':
    unittest.main()
