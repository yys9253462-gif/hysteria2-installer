"""回归测试：portal.py AWG 安装端口防前导零、awg-state 死线续期、warp-status 常规文件校验、cores 版本清洗与 reply 响应头防控制字符注入。"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')


class PortalAwgPortDeadlineWarpIsregCoresAndReplyHeaderGuardsTests(unittest.TestCase):
    def test_install_amneziawg_rejects_leading_zero_port_and_uses_clean_hop_range(self):
        """_h_post_install_amneziawg 须限制超长数字端口并用严格规则解析跳跃区间。"""
        start = SOURCE.index('def _h_post_install_amneziawg(self, prefix):')
        end = SOURCE.index('def _h_post_manage_amneziawg(self, prefix):', start)
        block = SOURCE[start:end]
        self.assertIn("len(port) > 10", block)
        self.assertIn("clean_hop_range(m_now.get('hop_port_range'))", block)

    def test_awg_state_endpoints_extend_deadline(self):
        """GET /awg-state 与 POST /manage-amneziawg(state) 均须续期连接死线防止子进程超时截断。"""
        m_start = SOURCE.index('def _h_post_manage_amneziawg(self, prefix):')
        m_end = SOURCE.index("known_actions = ('peer_add'", m_start)
        m_block = SOURCE[m_start:m_end]
        self.assertIn("self._extend_deadline(30)", m_block)

        g_start = SOURCE.index('def _h_get_awg_state(self, subpath):')
        g_end = SOURCE.index('def reply(self, code, body', g_start)
        g_block = SOURCE[g_start:g_end]
        self.assertIn("self._extend_deadline(30)", g_block)

    def test_warp_status_uses_isreg_cores_sanitizes_version_and_reply_strips_all_ctrl(self):
        """_h_get_warp_status 须用 stat.S_ISREG，_h_get_cores_status 须洗控制字符，reply 须拦截全部控制字符头名/头值。"""
        w_start = SOURCE.index('def _h_get_warp_status(self, subpath):')
        w_end = SOURCE.index('def _h_get_cert_status(self, subpath):', w_start)
        w_block = SOURCE[w_start:w_end]
        self.assertIn('S_ISREG(_wcfg_st.st_mode)', w_block)

        c_start = SOURCE.index('def _h_get_cores_status(self, subpath):')
        c_end = SOURCE.index('def _h_post_install_core(self, prefix):', c_start)
        c_block = SOURCE[c_start:c_end]
        self.assertIn("ord(ch) >= 32 and ord(ch) != 127", c_block)

        r_start = SOURCE.index('def reply(self, code, body')
        r_end = SOURCE.index('class ThreadingHTTPServer', r_start)
        r_block = SOURCE[r_start:r_end]
        self.assertIn("ord(ch) <= 32 or ord(ch) == 127 or ch == ':'", r_block)
        self.assertIn("''.join(ch for ch in str(mime) if ord(ch) >= 32 and ord(ch) != 127)", r_block)


if __name__ == '__main__':
    unittest.main()
