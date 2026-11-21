"""回归测试：计量运行时数值时间戳与缓存隔离、摘要健壮性、sampled_users 脏元素过滤及事件排序 OverflowError 防护。"""

import importlib.util
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_mod(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


core = _load_mod('test_um_core_53', 'usage-meter-core-20261007-v1.py')
runtime = _load_mod('test_um_runtime_53', 'usage-meter-runtime-20261007-v1.py')
readers = _load_mod('test_um_readers_53', 'usage-meter-readers-20261007-v1.py')


class UsageMeterNumericTsCacheAndDirtySampledUsersTests(unittest.TestCase):
    def test_recent_gaps_handles_numeric_timestamps_nan_and_returns_isolated_copy(self):
        """_recent_gaps 须正确识别过期数值时间戳、保守保留 NaN/Inf，并返回独立副本防污染缓存。"""
        old_ts = time.time() - 200000
        fresh_ts = time.time() - 10
        m = {
            'gaps': [
                {'source': 'hysteria', 'at': old_ts, 'reason': 'old_restart'},
                {'source': 'hysteria', 'at': fresh_ts, 'reason': 'recent_restart'},
                {'source': 'hysteria', 'at': float('nan'), 'reason': 'nan_ts'},
            ]
        }
        got1 = runtime._recent_gaps(m, window_seconds=86400)
        reasons = [g['reason'] for g in got1]
        self.assertEqual(reasons, ['recent_restart', 'nan_ts'],
                         '过期数值时间戳应被排除，近期数值时间戳与 NaN 应保留')
        # 外部篡改返回列表不得污染全局缓存
        got1.clear()
        got2 = runtime._recent_gaps(m, window_seconds=86400)
        self.assertEqual([g['reason'] for g in got2], ['recent_restart', 'nan_ts'],
                         '修改 _recent_gaps 返回值不得污染内部缓存')

    def test_source_fresh_accepts_numeric_timestamps_and_rejects_nan_bool(self):
        """_source_fresh 须与 apply_sample 一致接受有限数值时间戳，并拒绝 bool/nan。"""
        now = time.time()
        self.assertTrue(runtime._source_fresh({'hysteria': {'ok': True, 'sampled_at': now - 5}}, 'hysteria'))
        self.assertFalse(runtime._source_fresh({'hysteria': {'ok': True, 'sampled_at': now - 120}}, 'hysteria'))
        self.assertFalse(runtime._source_fresh({'hysteria': {'ok': True, 'sampled_at': float('nan')}}, 'hysteria'))
        self.assertFalse(runtime._source_fresh({'hysteria': {'ok': True, 'sampled_at': True}}, 'hysteria'))

    def test_summary_coerces_non_dict_health_entry_and_bad_online_count(self):
        """summary() 遇损坏 health[s]=None 或非整数 online_counts 值不得透传脏数据。"""
        data = {
            'users': {'u1': {'used_bytes': 10}},
            'usage_meter': {
                'sources': {'hysteria': {'epoch': 'e1', 'counters': {'u1': {'tx': 1, 'rx': 2}}}},
                'totals': {'u1': {'hysteria': 3}},
                'health': {'hysteria': None},
                'gaps': [],
            },
        }
        meter = runtime.PortalMeter(
            data, threading.RLock(), lambda: None,
            {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'}},
            read=lambda s, c: {},
        )
        meter.online_counts = {'u1': True}
        meter.online_sampled_at = time.time()
        s = meter.summary('u1')
        self.assertEqual(s['measurement_sources']['hysteria'], {})
        self.assertEqual(s['online_devices'], 0)

    def test_apply_sample_filters_dirty_sampled_users_without_dropping_valid_users(self):
        """previous.sampled_users 混入单个脏元素时不得清空全部合法用户导致漏计流量。"""
        state = {
            'sources': {
                'hysteria': {
                    'epoch': 'ep1',
                    'counters': {'alice': {'tx': 100, 'rx': 200}},
                    'sampled_at': '2026-11-22T00:00:00+00:00',
                    'sampled_users': [None, 'alice'],
                }
            },
            'totals': {'alice': {'hysteria': 50}},
            'gaps': [],
        }
        res = core.apply_sample(
            state, 'hysteria', 'ep1',
            {'alice': {'tx': 150, 'rx': 260}},
            '2026-11-22T00:00:05+00:00',
            active_users={'alice'},
        )
        self.assertEqual(state['totals']['alice']['hysteria'], 50 + 50 + 60,
                         '单个脏元素不得让 alice 退化为基线而丢掉增量流量')
        self.assertEqual(res['deltas'].get('alice'), (50, 60))

    def test_parse_events_converts_infinite_timestamp_overflow_to_value_error(self):
        """parse_events 遇到 float('inf') 等非有限时间戳必须抛出 ValueError 而非裸 OverflowError。"""
        bad_rows = [{'__MONOTONIC_TIMESTAMP': float('inf'), 'MESSAGE': 'hello'}]
        with self.assertRaises(ValueError):
            readers.parse_events(bad_rows)


if __name__ == '__main__':
    unittest.main()
