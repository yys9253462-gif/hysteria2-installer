"""回归测试：vmess / anytls / tuic / vlessenc 四个协议状态端点在调用 qrencode 前均须续期死线。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'


class ProtocolStatusEndpointsDeadlineTests(unittest.TestCase):
    def test_all_four_protocol_status_handlers_extend_deadline(self):
        src = PORTAL.read_text(encoding='utf-8')
        handlers = (
            ('_h_get_vmess_status', '_h_get_cores_status'),
            ('_h_get_anytls_status', '_apply_tuic_enable'),
            ('_h_get_tuic_status', '_h_post_manage_vlessenc'),
            ('_h_get_vlessenc_status', '_h_post_set_bbr'),
        )
        for name, next_name in handlers:
            start = src.index(f'def {name}(self, subpath):')
            end = src.index(f'def {next_name}(', start)
            block = src[start:end]
            self.assertIn('self._extend_deadline(30)', block, f'{name} 调 qrencode 前未续期死线')


if __name__ == '__main__':
    unittest.main()
