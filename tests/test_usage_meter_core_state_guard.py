"""回归测试：usage-meter-core 拦截非字典 state 与非有限/布尔 sampled_at，统一抛出 ValueError。"""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('usage_core_mod', ROOT / 'usage-meter-core-20261007-v1.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class UsageMeterCoreStateGuardTests(unittest.TestCase):
    def test_non_dict_state_raises_value_error_in_all_entrypoints(self):
        for bad in (None, [], 'corrupt', 123):
            with self.assertRaises(ValueError):
                MOD.apply_sample(bad, 'hysteria', 'ep1', {}, 1000)
            with self.assertRaises(ValueError):
                MOD.total_bytes(bad, 'u1')
            with self.assertRaises(ValueError):
                MOD.adjusted_bytes(bad, 'u1')

    def test_invalid_sampled_at_rejected_without_mutating_state(self):
        for bad_ts in (True, False, None, '', '   ', float('nan'), float('inf'), []):
            state = {'totals': {'u1': {'hysteria': 10}}}
            with self.assertRaises(ValueError):
                MOD.apply_sample(state, 'hysteria', 'ep1', {'u1': {'tx': 5, 'rx': 5}}, bad_ts)
            self.assertEqual(state, {'totals': {'u1': {'hysteria': 10}}})

        # 合法 ISO 字符串与有限时间戳均放行
        for ok_ts in ('2026-10-12T00:00:00Z', 1700000000):
            state = {}
            MOD.apply_sample(state, 'hysteria', 'ep1', {'u1': {'tx': 5, 'rx': 5}}, ok_ts)
            self.assertEqual(state['sources']['hysteria']['sampled_at'], ok_ts)


if __name__ == '__main__':
    unittest.main()
