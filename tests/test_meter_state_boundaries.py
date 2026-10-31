"""恢复的诊断字段或账户记录损坏时保留累计并继续采样。"""
import copy
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('meter_state_boundaries', ROOT / 'usage-meter-runtime-20261007-v1.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class MeterStateBoundaryTests(unittest.TestCase):
    def make_meter(self):
        self.data = {'users': {'u': {'used_bytes': 0}}}
        self.counters = {'u': {'tx': 0, 'rx': 0}}
        return runtime.PortalMeter(self.data, threading.RLock(), lambda: None,
            {'hysteria': {'test': True}}, read=lambda *_: copy.deepcopy(self.counters),
            epoch=lambda _: 'epoch')

    def test_corrupt_health_is_rebuilt_without_losing_totals(self):
        for bad in (None, [], 'broken', 7):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                meter.poll()
                self.counters['u']['tx'] = 10
                meter.poll()
                self.data['usage_meter']['health'] = bad
                self.counters['u']['tx'] = 25
                meter.poll()
                self.assertEqual(self.data['users']['u']['used_bytes'], 25)
                self.assertTrue(meter.summary('u')['measurement_current_ok'])

    def test_corrupt_health_with_reader_failure_records_failure(self):
        meter = self.make_meter()
        meter.poll()
        self.data['usage_meter']['health'] = []
        def failed_read(*_):
            raise OSError('unavailable')
        meter.read = failed_read
        meter.poll()
        self.assertFalse(meter.summary('u')['measurement_current_ok'])
        self.assertEqual(self.data['usage_meter']['health']['hysteria']['error'], 'OSError')

    def test_corrupt_health_summary_is_unhealthy_without_exception(self):
        for bad in (None, [], 'broken', 7):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                meter.poll()
                self.data['usage_meter']['health'] = bad
                self.assertFalse(meter.summary('u')['measurement_current_ok'])
                self.assertFalse(meter.hot_summary('u')['measurement_ok'])

    def test_cached_gap_window_detects_in_place_edit(self):
        from unittest.mock import patch
        state = {'gaps': [{'at': '2000-01-01T00:00:00+00:00', 'reason': 'old'}]}
        with patch.object(runtime.time, 'time', return_value=1793404800):
            self.assertEqual(runtime._recent_gaps(state), [])
            state['gaps'][0]['at'] = '2026-10-30T00:00:00+00:00'
            self.assertEqual(runtime._recent_gaps(state), state['gaps'])
            self.assertEqual(runtime._recent_gaps(state), state['gaps'])

    def test_failed_health_save_does_not_restore_deleted_usage_totals(self):
        meter = self.make_meter()
        meter.poll()
        self.counters['u']['tx'] = 10
        meter.poll()
        original_meter = self.data['usage_meter']
        def failed_read(*_):
            raise OSError('reader unavailable')
        def failed_save():
            self.data['usage_meter']['totals'].pop('u', None)
            self.data['usage_meter']['admin_note'] = 'concurrent change'
            raise OSError('disk full')
        meter.read = failed_read
        meter.save = failed_save
        meter.poll()
        self.assertIs(self.data['usage_meter'], original_meter)
        self.assertNotIn('u', self.data['usage_meter']['totals'])
        self.assertEqual(self.data['usage_meter']['admin_note'], 'concurrent change')

    def test_corrupt_sources_container_recovers_with_gap(self):
        for bad in (None, [], 'broken', 7):
            with self.subTest(sources=bad):
                state = {'sources': bad, 'totals': {'u': {'hysteria': 10}}}
                outcome = runtime.core.apply_sample(state, 'hysteria', 'epoch',
                    {'u': {'tx': 25, 'rx': 0}}, '2026-11-01T00:00:00+00:00')
                self.assertTrue(outcome['baseline_only'])
                self.assertEqual(runtime.core.total_bytes(state, 'u'), 10)
                self.assertIsInstance(state['sources'], dict)
                self.assertEqual(state['gaps'][-1]['reason'], 'corrupt_sources_reset')

    def test_corrupt_gaps_container_recovers_without_losing_usage(self):
        for bad in (None, [], 'broken', 7):
            if bad == []:
                continue
            with self.subTest(gaps=bad):
                state = {'sources': {'hysteria': {'epoch': 'epoch',
                    'counters': {'u': {'tx': 5, 'rx': 0}}, 'sampled_users': ['u']}},
                    'gaps': bad, 'totals': {'u': {'hysteria': 10}}}
                outcome = runtime.core.apply_sample(state, 'hysteria', 'epoch',
                    {'u': {'tx': 15, 'rx': 0}}, '2026-11-01T00:00:00+00:05:00')
                self.assertEqual(runtime.core.total_bytes(state, 'u'), 20)
                self.assertIsInstance(state['gaps'], list)
                self.assertTrue(any(g['reason'] == 'corrupt_gaps_reset' for g in state['gaps']))
                self.assertEqual(outcome['deltas']['u'], (10, 0))

    def test_invalid_gaps_never_report_complete_or_healthy(self):
        meter = self.make_meter()
        meter.poll()
        self.data['usage_meter']['gaps'] = None
        summary = meter.summary('u')
        self.assertFalse(summary['measurement_ok'])
        self.assertFalse(summary['measurement_complete'])
        self.assertTrue(any(g.get('reason') == 'invalid_gaps_container'
                            for g in summary['measurement_gaps']))

    def test_empty_saved_epoch_rebases_without_charging_process_history(self):
        state = {'sources': {'hysteria': {'epoch': '', 'counters': {'u': {'tx': 5, 'rx': 0}}}},
                 'totals': {'u': {'hysteria': 10}}}
        result = runtime.core.apply_sample(state, 'hysteria', 'epoch',
            {'u': {'tx': 1000, 'rx': 0}}, '2026-10-30T00:00:00+00:00')
        self.assertEqual(runtime.core.total_bytes(state, 'u'), 10)
        self.assertTrue(result['baseline_only'])
        self.assertEqual(state['gaps'][-1]['reason'], 'corrupt_state_reset')

    def test_missing_counter_does_not_turn_accumulated_usage_into_speed_spike(self):
        meter = self.make_meter()
        meter.poll()
        self.counters = {}
        meter.poll()
        samples = []
        meter.on_speed = lambda *args: samples.append(args)
        self.counters = {'u': {'tx': 25, 'rx': 0}}
        meter.poll()
        self.assertEqual(self.data['users']['u']['used_bytes'], 25)
        self.assertEqual(samples, [])
        self.counters['u']['tx'] = 30
        meter.poll()
        self.assertEqual(samples[-1][1:3], (5, 0))

    def test_corrupt_sampled_users_does_not_block_accounting(self):
        for bad in (None, 7, 'u', [['u']]):
            with self.subTest(bad=bad):
                state = {'sources': {'hysteria': {'epoch': 'epoch',
                    'counters': {'u': {'tx': 5, 'rx': 0}}, 'sampled_users': bad}},
                    'totals': {'u': {'hysteria': 10}}}
                result = runtime.core.apply_sample(state, 'hysteria', 'epoch',
                    {'u': {'tx': 15, 'rx': 0}}, '2026-10-30T00:00:00+00:00')
                self.assertEqual(runtime.core.total_bytes(state, 'u'), 20)
                self.assertEqual(result['deltas'], {})
                self.assertEqual(state['sources']['hysteria']['sampled_users'], ['u'])

    def test_corrupt_user_summary_returns_unavailable_legacy_value(self):
        meter = self.make_meter()
        meter.poll()
        for bad in (None, [], 'broken', 7):
            with self.subTest(bad=bad):
                self.data['users']['bad'] = bad
                self.assertIsNone(meter.summary('bad')['legacy_auth_value'])
                self.assertEqual(meter.summary('u')['legacy_auth_value'], 0)


if __name__ == '__main__':
    unittest.main()
