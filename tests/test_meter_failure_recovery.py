"""计量写盘失败恢复与健康状态的行为回归。"""
import ast
import copy
import importlib.util
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('meter_recovery', ROOT / 'usage-meter-runtime-20261007-v1.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class MeterRecoveryTests(unittest.TestCase):
    def make_meter(self):
        self.data = {'users': {'u': {'password': 'fixture', 'used_bytes': 0}}}
        self.counters = {'u': {'tx': 0, 'rx': 0}}
        self.speeds = []
        return runtime.PortalMeter(self.data, threading.RLock(), lambda: None,
            {'hysteria': {'test': True}}, read=lambda *_: copy.deepcopy(self.counters),
            epoch=lambda _: 'epoch', on_speed=lambda *args: self.speeds.append(args))

    def test_retry_uses_last_committed_sample_interval(self):
        meter = self.make_meter()
        with patch.object(runtime.time, 'monotonic', return_value=100):
            meter.poll()
        meter.save = Mock(side_effect=OSError('disk full'))
        self.counters['u']['tx'] = 50
        with patch.object(runtime.time, 'monotonic', return_value=105):
            meter.poll()
        meter.save = lambda: None
        self.counters['u']['tx'] = 100
        with patch.object(runtime.time, 'monotonic', return_value=110):
            meter.poll()
        self.assertEqual(self.data['users']['u']['used_bytes'], 100)
        self.assertEqual(self.speeds[-1][1:4], (100, 0, 10))

    def test_corrupt_unrelated_user_does_not_disable_meter(self):
        meter = self.make_meter()
        self.data['users']['broken'] = None
        meter.poll()
        self.counters['u']['tx'] = 25
        meter.poll()
        self.assertEqual(self.data['users']['u']['used_bytes'], 25)
        self.assertTrue(meter.summary('u')['measurement_current_ok'])
        self.assertIsNone(self.data['users']['broken'])

    def test_failed_save_preserves_concurrent_user_changes(self):
        meter = self.make_meter()
        meter.poll()
        original = self.data['users']['u']
        self.counters['u']['tx'] = 25
        calls = []

        def save():
            calls.append(1)
            if len(calls) == 1:
                with meter.lock:
                    original['status'] = 'disabled'
                    self.data['users']['new'] = {'password': 'new-user'}
                raise OSError('disk full')
        meter.save = save
        meter.poll()
        self.assertIs(self.data['users']['u'], original)
        self.assertEqual(original['status'], 'disabled')
        self.assertEqual(original['used_bytes'], 0)
        self.assertIn('new', self.data['users'])

    def test_failed_save_does_not_resurrect_deleted_user(self):
        meter = self.make_meter()
        meter.poll()
        self.counters['u']['tx'] = 25
        calls = []

        def save():
            calls.append(1)
            if len(calls) == 1:
                with meter.lock:
                    del self.data['users']['u']
                raise OSError('disk full')
        meter.save = save
        meter.poll()
        self.assertNotIn('u', self.data['users'])

    def test_portal_save_propagates_write_error_without_fallback(self):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                    and n.name == 'save_data')
        write = Mock(side_effect=OSError('disk full'))
        fallback = Mock()
        fallback.exists.return_value = False
        env = {'data': {'users': {}}, 'data_lock': threading.RLock(),
               'json': __import__('json'), 'portal_path': Path('/fixture/portal.json'),
               'atomic_write_private': write, 'Path': Mock(return_value=fallback)}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<portal-save>', 'exec'), env)
        with self.assertRaises(OSError):
            env['save_data']()
        write.assert_called_once()

    def test_future_health_sample_is_not_fresh(self):
        with patch.object(runtime.time, 'time', return_value=100):
            self.assertFalse(runtime._source_fresh(
                {'hysteria': {'ok': True, 'sampled_at': '2099-01-01T00:00:00+00:00'}},
                'hysteria'))

    def test_first_meter_save_is_not_skipped_during_initial_minute(self):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                    and n.name == 'save_meter_data')
        save = Mock()
        clock = SimpleNamespace(monotonic=lambda: 5)
        env = {'time': clock, '_meter_last_save': [None], 'METER_SAVE_INTERVAL': 60,
               'save_data': save}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<meter-save>', 'exec'), env)
        env['save_meter_data']()
        save.assert_called_once_with()
        self.assertEqual(env['_meter_last_save'][0], 5)

    def test_failed_save_does_not_throttle_immediate_retry(self):
        tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                    and n.name == 'save_meter_data')
        save = Mock(side_effect=[OSError('disk full'), None])
        clock = SimpleNamespace(monotonic=lambda: 100)
        env = {'time': clock, '_meter_last_save': [None], 'METER_SAVE_INTERVAL': 60,
               'save_data': save}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<meter-save>', 'exec'), env)
        with self.assertRaises(OSError):
            env['save_meter_data']()
        env['save_meter_data']()
        self.assertEqual(save.call_count, 2)
        self.assertEqual(env['_meter_last_save'][0], 100)


if __name__ == '__main__':
    unittest.main()
