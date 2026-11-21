"""回归测试：Reality 启用写入 enabled=True、停用持久化 enabled=False 并释放端口占用判定，且保存失败回滚入站。"""

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class RealityDisableStatePersistenceTests(unittest.TestCase):
    def test_reality_enable_sets_enabled_true_and_disable_persists_false_with_rollback(self):
        gen_start = SRC.index('        def _generate_and_apply_reality(')
        gen_end = SRC.index('        def _apply_vmess_enable(', gen_start)
        gen_body = SRC[gen_start:gen_end]
        self.assertIn("'enabled': True", gen_body,
                      '_generate_and_apply_reality 必须显式写入 enabled=True 以便停用后与启停语义一致')

        mgr_start = SRC.index('        def _h_post_manage_reality(self, prefix):')
        mgr_end = SRC.index("                elif action == 'reset':", mgr_start)
        mgr_body = SRC[mgr_start:mgr_end]
        self.assertIn("['enabled'] = False", mgr_body,
                      '停用 Reality 必须将 data[reality_config][enabled] 置为 False 并持久化，避免旧端口永久被误判占用')
        self.assertIn('save_data()', mgr_body,
                      '停用 Reality 必须调用 save_data() 持久化 enabled=False 并在失败时回滚')

    def test_protocol_port_in_use_frees_port_when_reality_disabled(self):
        data_enabled = {'reality_config': {'port': 443, 'enabled': True}}
        data_disabled = {'reality_config': {'port': 443, 'enabled': False}}
        with mock.patch.object(portal, '_systemd_state', return_value='inactive'):
            self.assertTrue(portal.protocol_port_in_use(443, 'tcp', data_enabled))
            self.assertFalse(portal.protocol_port_in_use(443, 'tcp', data_disabled))


if __name__ == '__main__':
    unittest.main()
