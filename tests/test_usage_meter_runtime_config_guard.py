"""回归测试：usage-meter-runtime 对非对象配置须显式抛 ValueError，summary 容忍损坏采样时间戳。"""

import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_runtime():
    spec = importlib.util.spec_from_file_location(
        'usage_meter_runtime_guard_probe',
        ROOT / 'usage-meter-runtime-20261007-v1.py',
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterRuntimeConfigGuardTests(unittest.TestCase):
    def test_from_file_and_init_reject_non_dict_config_with_value_error(self):
        """usage-meter-config.json 为数组或 null 时，初始化阶段即应抛 ValueError 而非延后 AttributeError。"""
        mod = _load_runtime()
        for bad in ([], None, 'broken', 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    mod.PortalMeter({}, threading.RLock(), lambda: None, bad)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'usage-meter-config.json'
            p.write_text(json.dumps(['not-a-dict']), encoding='utf-8')
            with self.assertRaises(ValueError):
                mod.from_file({}, threading.RLock(), lambda: None, p)

    def test_summary_tolerates_corrupt_sampled_at_timestamps(self):
        """live_sampled_at 或 online_sampled_at 被破坏为非数字时，summary() 必须安全降级不得抛 TypeError。"""
        mod = _load_runtime()
        meter = mod.PortalMeter({'users': {'u1': {}}}, threading.RLock(), lambda: None, {})
        meter.live_snapshot = {'users': {'u1': {'ips': ['1.1.1.1'], 'ok': True}}}
        meter.live_sampled_at = 'corrupt'
        meter.online_counts = {'u1': 1}
        meter.online_sampled_at = None
        summary = meter.summary('u1')
        self.assertFalse(summary['current_online']['ok'])
        self.assertIsNone(summary['online_devices'])


if __name__ == '__main__':
    unittest.main()
