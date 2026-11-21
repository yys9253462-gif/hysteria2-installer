"""回归测试：计量核心与运行时在容器损坏、空采样与时钟回拨场景下的安全防护。"""
import importlib.util
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


core = _load('um_core_guard', 'usage-meter-core-20261007-v1.py')
runtime = _load('um_runtime_guard', 'usage-meter-runtime-20261007-v1.py')


class UsageMeterBoundaryGuardsTests(unittest.TestCase):
    def test_apply_sample_rejects_corrupt_totals_even_when_counters_empty(self):
        state = {'totals': None, 'retired_users': ['old']}
        with self.assertRaisesRegex(ValueError, 'invalid totals'):
            core.apply_sample(state, 'hysteria', 'ep1', {}, '2026-11-21T00:00:00+00:00')

        state2 = {'totals': ['bad']}
        with self.assertRaisesRegex(ValueError, 'invalid totals'):
            core.apply_sample(state2, 'hysteria', 'ep1', {}, '2026-11-21T00:00:00+00:00')

    def test_summary_handles_malformed_live_snapshot_and_clock_backward_jump(self):
        data = {'users': {'u1': {'used_bytes': 0}}, 'usage_meter': {}}
        meter = runtime.PortalMeter(data, threading.RLock(), lambda: None, {'hysteria': {'url': 'http://127.0.0.1', 'secret': 's'}},
                                    read=lambda s, c: {}, epoch=lambda svc: 'ep1')
        # 1) live_snapshot.users 为 None 时 summary 不能抛 AttributeError
        meter.live_snapshot = {'users': None}
        meter.live_sampled_at = time.time()
        meter.online_counts = 'not-a-dict'
        meter.online_sampled_at = time.time()
        s = meter.summary('u1')
        self.assertEqual(s['current_online']['ips'], [])
        self.assertIsNone(s['online_devices'])

        # 2) 时钟回拨（sampled_at 落在未来）不能把陈旧缓存误当成新鲜
        meter.live_snapshot = {'users': {'u1': {'ips': ['1.2.3.4'], 'ok': True}}}
        meter.live_sampled_at = time.time() + 120
        meter.online_counts = {'u1': 3}
        meter.online_sampled_at = time.time() + 120
        s2 = meter.summary('u1')
        self.assertFalse(s2['current_online']['ok'], '时钟回拨时未来时间戳快照不应判为新鲜')
        self.assertIsNone(s2['online_devices'], '时钟回拨时未来时间戳在线设备数不应判为新鲜')

    def test_poll_marks_source_failed_when_usage_meter_container_corrupt(self):
        data = {'users': {'u1': {'used_bytes': 0}}, 'usage_meter': ['corrupt']}
        meter = runtime.PortalMeter(data, threading.RLock(), lambda: None, {'hysteria': {'url': 'http://127.0.0.1', 'secret': 's'}},
                                    read=lambda s, c: {}, epoch=lambda svc: 'ep1')
        meter.poll()
        self.assertIn('hysteria', meter.failed_sources)
        # 损坏原件必须保留不被清零
        self.assertEqual(data['usage_meter'], ['corrupt'])


if __name__ == '__main__':
    unittest.main()
