"""损坏财务状态不能产生半提交计量或杀死采样循环。"""
import copy
import importlib.util
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('meter_transaction_integrity', ROOT / 'usage-meter-runtime-20261007-v1.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class MeterTransactionIntegrityTests(unittest.TestCase):
    def make_meter(self):
        self.data = {'users': {'u': {'used_bytes': 0}, 'broken': {'used_bytes': 50}}}
        self.counters = {'u': {'tx': 0, 'rx': 0}}
        self.saved = []
        return runtime.PortalMeter(self.data, threading.RLock(),
            lambda: self.saved.append(copy.deepcopy(self.data)),
            {'hysteria': {'test': True}}, read=lambda *_: copy.deepcopy(self.counters),
            epoch=lambda _: 'epoch')

    def test_malformed_reality_config_does_not_stop_hysteria_sampling(self):
        from unittest.mock import patch
        for bad in ('broken', {'binary': None}, {'binary': []}):
            with self.subTest(bad=bad):
                data = {'users': {'u': {'used_bytes': 0}}}
                counters = {'u': {'tx': 0, 'rx': 0}}
                meter = runtime.PortalMeter(data, threading.RLock(), lambda: None,
                    {'hysteria': {'url': 'http://127.0.0.1:1', 'secret': 'x'},
                     'reality': bad}, epoch=lambda _: 'epoch')
                with patch.object(runtime.readers, 'read_live_connections', return_value={}), \
                     patch.object(runtime.readers, 'read_hysteria', side_effect=lambda *_: copy.deepcopy(counters)), \
                     patch.object(runtime.readers, 'read_hysteria_online', return_value={}):
                    meter.poll()
                    counters['u']['tx'] = 25
                    meter.poll()
                self.assertEqual(data['users']['u']['used_bytes'], 25)
                self.assertFalse(data['usage_meter']['health']['reality']['ok'])

    def test_post_replace_sync_failure_does_not_double_count(self):
        class DurabilityError(OSError):
            replaced = True
        meter = self.make_meter()
        meter.poll()
        self.counters['u']['tx'] = 25
        meter.save = lambda: (_ for _ in ()).throw(DurabilityError('directory sync'))
        meter.poll()
        self.assertEqual(self.data['users']['u']['used_bytes'], 25)
        self.assertEqual(self.data['usage_meter']['sources']['hysteria']['counters']['u']['tx'], 25)
        self.assertFalse(meter.summary('u')['measurement_current_ok'])
        meter.save = lambda: None
        meter.poll()
        self.assertEqual(self.data['users']['u']['used_bytes'], 25)

    def test_persistent_save_failure_reports_unhealthy_in_memory(self):
        meter = self.make_meter()
        meter.poll()
        meter.save = lambda: (_ for _ in ()).throw(OSError('disk full'))
        self.counters['u']['tx'] = 25
        meter.poll()
        self.assertFalse(meter.summary('u')['measurement_current_ok'])
        self.assertTrue(self.data['usage_meter']['health']['hysteria']['ok'])
        self.assertIn('hysteria', meter.failed_sources)
        meter.save = lambda: None
        meter.poll()
        self.assertNotIn('hysteria', meter.failed_sources)
        self.assertTrue(meter.summary('u')['measurement_current_ok'])

    def test_corrupt_total_does_not_partially_update_users(self):
        meter = self.make_meter()
        meter.poll()
        self.data['usage_meter']['totals']['broken'] = None
        before = copy.deepcopy(self.data['users'])
        self.counters['u']['tx'] = 25
        meter.poll()
        self.assertEqual(self.data['users'], before)
        self.assertEqual(self.data['usage_meter']['sources']['hysteria']['counters']['u']['tx'], 0)
        self.assertFalse(self.data['usage_meter']['health']['hysteria']['ok'])
        for snapshot in self.saved[1:]:
            self.assertEqual(snapshot['users'], before)

    def test_corrupt_meter_container_never_escapes_poll_or_claims_health(self):
        for bad in (None, [], 'broken', 7):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                self.data['usage_meter'] = bad
                before = copy.deepcopy(self.data)
                meter.poll()
                self.assertEqual(self.data, before)
                for result in (meter.summary('u'), meter.hot_summary('u')):
                    self.assertIsNone(result['measured_bytes'])
                    self.assertFalse(result['measurement_ok'])

    def test_negative_or_boolean_total_cannot_be_laundered_by_new_delta(self):
        for bad in (-1, True, 1.5):
            with self.subTest(bad=bad):
                state = {'sources': {'hysteria': {'epoch': 'epoch',
                    'counters': {'u': {'tx': 0, 'rx': 0}}}},
                    'totals': {'u': {'hysteria': bad}}}
                before = copy.deepcopy(state)
                with self.assertRaises(ValueError):
                    runtime.core.apply_sample(state, 'hysteria', 'epoch',
                        {'u': {'tx': 25, 'rx': 0}}, '2026-10-30T00:00:00+00:00')
                self.assertEqual(state, before)

    def test_unrepresentable_saved_timestamps_are_unhealthy(self):
        from unittest.mock import patch
        for error in (OSError('timestamp range'), OverflowError('timestamp range')):
            with self.subTest(error=type(error).__name__):
                with patch.object(runtime, 'datetime') as clock:
                    clock.fromisoformat.return_value.timestamp.side_effect = error
                    self.assertFalse(runtime._source_fresh({'hysteria': {
                        'ok': True, 'sampled_at': '0001-01-01T00:00:00'}}, 'hysteria'))
                    state = {'gaps': [{'at': '0001-01-01T00:00:00'}]}
                    runtime._recent_gaps_cache['key'] = None
                    self.assertEqual(runtime._recent_gaps(state), state['gaps'])

    def test_corrupt_source_cannot_claim_initialized_measurement(self):
        for bad in (None, [], {}, {'epoch': '', 'counters': {}}, {'epoch': 'epoch', 'counters': []}):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                meter.poll()
                self.data['usage_meter']['sources']['hysteria'] = bad
                for result in (meter.summary('u'), meter.hot_summary('u')):
                    self.assertIsNone(result['measured_bytes'])
                    self.assertFalse(result['measurement_ok'])

    def test_reconciliation_waits_for_failed_sample_transaction(self):
        meter = self.make_meter()
        meter.poll()
        self.counters['u']['tx'] = 25
        entered, attempted, finished = threading.Event(), threading.Event(), threading.Event()
        calls = []
        def failed_save():
            calls.append(1)
            if len(calls) == 1:
                entered.set()
                self.assertTrue(attempted.wait(2))
                # Give the other thread a chance to enter the critical section.
                finished.wait(0.1)
                raise OSError('disk full')
        def reconcile():
            self.assertTrue(entered.wait(2))
            attempted.set()
            with meter.lock:
                state = self.data['usage_meter']
                state.setdefault('adjustments', {})['u'] = 100 - runtime.core.total_bytes(state, 'u')
                self.data['users']['u']['used_bytes'] = 100
            finished.set()
        meter.save = failed_save
        worker = threading.Thread(target=reconcile)
        worker.start()
        meter.poll()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        state = self.data['usage_meter']
        self.assertEqual(runtime.core.adjusted_bytes(state, 'u'), 100)
        self.assertEqual(self.data['users']['u']['used_bytes'], 100)
        meter.save = lambda: None
        meter.poll()
        self.assertEqual(self.data['users']['u']['used_bytes'], 125)

    def test_failed_sample_save_preserves_deleted_totals(self):
        meter = self.make_meter()
        meter.poll()
        self.counters['u']['tx'] = 10
        meter.poll()
        self.counters['u']['tx'] = 25
        calls = []
        def failed_save():
            calls.append(1)
            if len(calls) == 1:
                self.data['users'].pop('u')
                self.data['usage_meter']['totals'].pop('u')
                raise OSError('disk full')
        meter.save = failed_save
        meter.poll()
        self.assertNotIn('u', self.data['users'])
        self.assertNotIn('u', self.data['usage_meter']['totals'])

    def test_failed_sample_save_preserves_concurrent_meter_edits(self):
        meter = self.make_meter()
        meter.poll()
        self.counters['u']['tx'] = 25
        calls = []
        def failed_save():
            calls.append(1)
            if len(calls) == 1:
                self.data['usage_meter']['totals']['u']['hysteria'] = 90
                self.data['users']['u']['used_bytes'] = 90
                self.data['usage_meter']['admin_note'] = 'concurrent edit'
                raise OSError('disk full')
        meter.save = failed_save
        meter.poll()
        self.assertEqual(self.data['usage_meter']['totals']['u']['hysteria'], 90)
        self.assertEqual(self.data['users']['u']['used_bytes'], 90)
        self.assertEqual(self.data['usage_meter']['admin_note'], 'concurrent edit')
        self.assertEqual(self.data['usage_meter']['sources']['hysteria']['counters']['u']['tx'], 0)

    def test_failed_first_save_preserves_only_concurrent_new_totals(self):
        meter = self.make_meter()
        calls = []
        def failed_save():
            calls.append(1)
            if len(calls) == 1:
                self.data['usage_meter']['totals']['admin-added'] = {'hysteria': 90}
                raise OSError('disk full')
        meter.save = failed_save
        meter.poll()
        self.assertEqual(self.data['usage_meter']['totals'],
                         {'admin-added': {'hysteria': 90}})
        self.assertNotIn('sources', self.data['usage_meter'])
        self.assertEqual(self.data['users']['u']['used_bytes'], 0)

    def test_corrupt_user_container_keeps_sampling_and_summary_alive(self):
        # users 被手工改成 null/list/str 时，采样线程与 summary 都不能抛异常：
        # 前者一退出就再也不计量，后者让控制台所有用量显示 500。
        for bad in (None, ['u'], 'oops', 7):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                self.data['users'] = bad
                self.counters['u']['tx'] = 25
                meter.poll()
                meter.poll()
                self.assertEqual(self.data['users'], bad)
                self.assertIsNotNone(meter.summary('u')['measured_bytes'])
                self.assertIsNotNone(meter.hot_summary('u')['measured_bytes'])

    def test_corrupt_totals_container_keeps_last_known_account_usage(self):
        for bad in (None, [], 'broken', 7):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                meter.poll()
                self.data['usage_meter']['totals'] = bad
                before = copy.deepcopy(self.data['users'])
                self.counters['u']['tx'] = 25
                meter.poll()
                self.assertEqual(self.data['users'], before)
                self.assertEqual(self.data['usage_meter']['totals'], bad)
                self.assertIsNone(meter.summary('u')['measured_bytes'])
                self.assertFalse(meter.hot_summary('u')['measurement_ok'])

    def test_corrupt_totals_summary_reports_unknown(self):
        for bad in (None, [], 'broken', {'hysteria': '12'}, {'hysteria': -1}, {'hysteria': True}):
            with self.subTest(bad=bad):
                meter = self.make_meter()
                meter.poll()
                self.data['usage_meter']['totals']['u'] = bad
                for result in (meter.summary('u'), meter.hot_summary('u')):
                    self.assertIsNone(result['measured_bytes'])
                    self.assertFalse(result['measurement_ok'])
                self.assertEqual(self.data['usage_meter']['totals']['u'], bad)


if __name__ == '__main__':
    unittest.main()
