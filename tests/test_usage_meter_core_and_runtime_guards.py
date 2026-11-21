"""回归测试：计量核心跳过已退役用户的坏 totals 与防字符串 active_users，及运行时坏 binary 路径不打崩摘要。"""
import importlib.util
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def _load(mod_name, filename):
    spec = importlib.util.spec_from_file_location(mod_name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterCoreAndRuntimeGuardsTests(unittest.TestCase):
    def test_apply_sample_clears_retired_corrupt_totals_without_breaking_active_users(self):
        """已退役用户在 totals 中残留损坏值时，apply_sample 应清理该退役条目而不中断正常用户计量。"""
        core = _load('meter_core_guard_test', 'usage-meter-core-20261007-v1.py')
        state = {
            'retired_users': ['deleted_u'],
            'totals': {
                'deleted_u': 'corrupt-not-a-dict',
                'alice': {'hysteria': 100},
            },
            'sources': {
                'hysteria': {
                    'epoch': 'ep1',
                    'counters': {'alice': {'tx': 50, 'rx': 50}},
                    'sampled_users': ['alice'],
                }
            },
        }
        core.apply_sample(
            state,
            'hysteria',
            'ep1',
            {'deleted_u': {'tx': 10, 'rx': 20}, 'alice': {'tx': 80, 'rx': 70}},
            '2026-11-22T00:00:00Z',
            active_users={'alice'},
        )
        self.assertNotIn('deleted_u', state['totals'])
        self.assertEqual(state['totals']['alice']['hysteria'], 150)

    def test_apply_sample_rejects_string_or_non_iterable_active_users(self):
        """active_users 误传字符串/字节串或非可迭代对象时必须抛 ValueError，避免把单字符当成用户 ID。"""
        core = _load('meter_core_active_test', 'usage-meter-core-20261007-v1.py')
        for bad in ('alice', b'alice', 123):
            with self.subTest(bad=bad):
                state = {}
                with self.assertRaises(ValueError):
                    core.apply_sample(
                        state,
                        'hysteria',
                        'ep1',
                        {'a': {'tx': 1, 'rx': 1}},
                        '2026-11-22T00:00:00Z',
                        active_users=bad,
                    )

    def test_runtime_configured_sources_and_summary_survive_bad_binary_path_oserror(self):
        """reality.binary 触发路径 OSError/ValueError 时，configured_sources / summary 不得打崩接口。"""
        runtime = _load('meter_runtime_guard_test', 'usage-meter-runtime-20261007-v1.py')
        meter = runtime.PortalMeter(
            data={'users': {'u1': {'used_bytes': 0}}},
            lock=threading.RLock(),
            save=Mock(),
            config={
                'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'},
                'reality': {'binary': '/usr/local/bin/' + 'a' * 5000, 'address': '127.0.0.1:10085'},
            },
        )
        from unittest.mock import patch
        with patch.object(runtime.pathlib.Path, 'is_file', side_effect=OSError('file name too long')):
            sources = meter.configured_sources()
            self.assertEqual(sources, ['hysteria'])
            summary = meter.summary('u1')
            self.assertIsInstance(summary, dict)
            self.assertIn('measurement_ok', summary)


if __name__ == '__main__':
    unittest.main()
