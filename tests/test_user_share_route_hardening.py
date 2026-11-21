"""回归测试：专属分享路由 u/<uid> 的错误密钥失败计数、二维码降级图、锁内令牌复用与端口清洗。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class UserShareRouteHardeningTests(unittest.TestCase):
    def _share_block(self) -> str:
        start = SRC.index("            if subpath.startswith('u/'):")
        end = SRC.index("            # 2. 版本检查与更新 API", start)
        return SRC[start:end]

    def test_invalid_share_key_records_failure_and_guards_ascii(self):
        body = self._share_block()
        deny_idx = body.index("return self.reply(403, b'Access denied: invalid key')")
        self.assertIn('self.record_failure()', body[:deny_idx],
                      '未鉴权访问 u/<uid>?k=... 失败时必须记入失败限流桶，防止暴力枚举')
        self.assertIn('expected_k.isascii()', body[:deny_idx])

    def test_share_qr_falls_back_to_unavailable_svg_and_avoids_unlocked_token_read(self):
        body = self._share_block()
        self.assertIn('QR_UNAVAILABLE_SVG', body,
                      'u/<uid>/qr.svg 在 qrencode 缺失或输出为空时应回退可读提示图，与管理页一致')
        self.assertNotIn("data['token']", body,
                         '渲染 user_page_html 应复用锁内已读取的 _portal_tok，不得在锁外裸读 data[token]')
        self.assertIn("_valid_port(m.get('listen_port')) or 19984", body,
                      'listen_port 应经 _valid_port 清洗，避免损坏 meta 把 None/坏值渲染进页面')


if __name__ == '__main__':
    unittest.main()
