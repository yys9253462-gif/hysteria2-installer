"""回归测试：计量模块 from_file / _read_bounded_json 零TOCTOU有界读盘，以及 _has_recent_gaps 零深拷贝热路径优化。"""

import copy
import importlib.util
import pathlib
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

REPO = pathlib.Path(__file__).resolve().parents[1]
READERS_SRC = (REPO / 'usage-meter-readers-20261007-v1.py').read_text(encoding='utf-8')
RUNTIME_SRC = (REPO / 'usage-meter-runtime-20261007-v1.py').read_text(encoding='utf-8')


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterNofollowFstatAndHotGapsZeroDeepcopyGuardsTests(unittest.TestCase):
    def test_readers_and_runtime_use_o_nofollow_and_fstat_for_bounded_config_reads(self):
        """_read_bounded_json 与 from_file 均须支持 O_NOFOLLOW + os.fstat 消除符号链接 TOCTOU 窗口。"""
        self.assertIn('O_NOFOLLOW', READERS_SRC)
        self.assertIn('os.fstat(fd)', READERS_SRC)
        self.assertIn('O_NOFOLLOW', RUNTIME_SRC)
        self.assertIn('os.fstat(fd)', RUNTIME_SRC)

    def test_hot_summary_uses_has_recent_gaps_without_deepcopy_on_cache_hit(self):
        """hot_summary / summary 的 measurement_ok 命中缓存时不得触发 copy.deepcopy 拷贝整份 gaps 列表。"""
        rt = _load('usage_meter_runtime_test_nodc', 'usage-meter-runtime-20261007-v1.py')
        self.assertTrue(hasattr(rt, '_has_recent_gaps'), '缺少轻量 _has_recent_gaps 辅助函数')

        now_iso = datetime.now(timezone.utc).isoformat()
        meter_state = {
            'sources': {
                'hysteria': {'epoch': 'e1', 'counters': {'u1': {'tx': 10, 'rx': 20}}},
            },
            'totals': {'u1': {'hysteria': 30}},
            'health': {'hysteria': {'ok': True, 'sampled_at': now_iso, 'error': ''}},
            'gaps': [{'source': 'hysteria', 'at': now_iso, 'reason': 'service_restart_unsampled_tail_unknown'} for _ in range(50)],
        }
        data = {'usage_meter': meter_state, 'users': {'u1': {'used_bytes': 30}}}
        pm = rt.PortalMeter(data, threading.RLock(), lambda: None, {'hysteria': {'url': 'http://127.0.0.1:9999', 'secret': 's'}}, read=lambda s, c: {})

        # 第一次预热缓存
        first = pm.hot_summary('u1')
        self.assertFalse(first['measurement_ok'])

        # 第二次缓存命中时，hot_summary 绝不可调用 copy.deepcopy
        with patch.object(copy, 'deepcopy', side_effect=AssertionError('热路径缓存命中不应执行 deepcopy')):
            second = pm.hot_summary('u1')
        self.assertFalse(second['measurement_ok'])
        self.assertEqual(second['measured_bytes'], 30)


if __name__ == '__main__':
    unittest.main()
