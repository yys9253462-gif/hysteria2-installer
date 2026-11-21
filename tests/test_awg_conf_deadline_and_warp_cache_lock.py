"""回归测试：_warp_probe_cache 并发加锁保护；awg-conf 补齐安全响应头；user-config 续期并校验节点元信息。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'


class AwgConfHeadersAndWarpCacheLockTests(unittest.TestCase):
    def test_warp_probe_cache_is_protected_by_lock(self):
        """_h_get_warp_status 读写 _warp_probe_cache 必须使用专用锁保护，防止并发读到撕裂的 (value, at)。"""
        src = PORTAL.read_text(encoding='utf-8')
        self.assertIn('_warp_probe_lock = threading.Lock()', src)
        start = src.index('        def _h_get_warp_status(self, subpath):')
        end = src.index('        def _h_get_cert_status(self, subpath):', start)
        block = src[start:end]
        self.assertIn('with _warp_probe_lock:', block)

    def test_awg_conf_sets_frame_and_referrer_headers_and_user_config_validates_meta(self):
        """awg-conf 下载响应必须补齐 X-Frame-Options 与 Referrer-Policy；user-config 须续期并拒绝空元信息。"""
        src = PORTAL.read_text(encoding='utf-8')
        awg_start = src.index("if awg_route in ('awg-conf', 'awg-qr.svg'):")
        awg_end = src.index("if not self.is_authenticated():", src.index("if awg_route == 'awg-conf':", awg_start))
        awg_block = src[awg_start:awg_end]
        self.assertIn("self.send_header('X-Frame-Options', 'DENY')", awg_block)
        self.assertIn("self.send_header('Referrer-Policy', 'no-referrer')", awg_block)

        uc_start = src.index("if subpath == 'user-config' or subpath.startswith('user-config?'):")
        uc_end = src.index("# ---------------- AmneziaWG (AWG) ----------------", uc_start)
        uc_block = src[uc_start:uc_end]
        self.assertIn('self._extend_deadline(30)', uc_block, 'user-config 调 10 秒 qrencode 前未续期')
        self.assertIn('节点元信息缺失或损坏', uc_block, 'user-config 未校验 client_meta.json 节点身份非空')

        login_start = awg_end
        login_end = src.index("if subpath == '':", login_start)
        login_block = src[login_start:login_end]
        self.assertIn('with data_lock:', login_block, '未认证登录页读取 data[token] 未加 data_lock')


if __name__ == '__main__':
    unittest.main()
