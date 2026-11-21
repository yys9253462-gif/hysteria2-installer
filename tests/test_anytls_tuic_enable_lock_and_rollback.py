"""回归测试：_apply_anytls_enable 须在 data_lock 内深拷贝 previous_cfg；_apply_tuic_enable 失败回滚原无配置须移除脏键。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'


class AnytlsTuicEnableLockAndRollbackTests(unittest.TestCase):
    def test_anytls_enable_copies_previous_cfg_inside_data_lock(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def _apply_anytls_enable(self):')
        end = src.index('def _h_post_manage_anytls(self, prefix):', start)
        block = src[start:end]
        lock_start = block.index('with data_lock:', block.index('with anytls_apply_lock:'))
        lock_end = block.index('previous_unit =', lock_start)
        lock_block = block[lock_start:lock_end]
        self.assertIn("previous_cfg = copy.deepcopy(config_section(data, 'anytls_config'))", lock_block,
                      '_apply_anytls_enable 在 data_lock 外读取并 deepcopy 全局 data')

    def test_tuic_enable_rollback_pops_key_when_previously_absent(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def _apply_tuic_enable(self):')
        end = src.index('def _h_post_manage_tuic(self, prefix):', start)
        block = src[start:end]
        rb_start = block.index('except Exception:', block.index('save_data()'))
        rb_block = block[rb_start:]
        self.assertIn("data.pop('tuic_config', None)", rb_block,
                      '_apply_tuic_enable 原无配置时失败回滚残留了空 tuic_config 键')


if __name__ == '__main__':
    unittest.main()
