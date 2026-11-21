"""回归测试：usage-meter-runtime 的 naive ISO 按 UTC 解析、新建用户缺失 live_snapshot 条目返回标准占位及坏源配置校验。"""

import importlib.util
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_runtime():
    path = ROOT / 'usage-meter-runtime-20261007-v1.py'
    spec = importlib.util.spec_from_file_location('usage_meter_runtime_tz_mod', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterRuntimeTzAndLiveEntryTests(unittest.TestCase):
    def test_naive_iso_timestamp_is_interpreted_as_utc_not_local_tz(self):
        mod = _load_runtime()
        # 构造当前 UTC 时间但不带时区后缀的 naive ISO 字符串
        naive_utc_now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        health = {'hysteria': {'ok': True, 'sampled_at': naive_utc_now}}
        self.assertTrue(mod._source_fresh(health, 'hysteria', max_age=30),
                        'naive UTC ISO 时间戳应按 UTC 解析，不能受系统本地时区偏移影响')

        # 距离当前超过 2 天的 naive UTC gap 应视为过期而非近期缺口
        old_naive = datetime.fromtimestamp(time.time() - 200000, tz=timezone.utc).replace(tzinfo=None).isoformat()
        self.assertEqual(mod._recent_gaps({'gaps': [{'at': old_naive, 'reason': 'old'}]}, window_seconds=86400), [])

    def test_summary_returns_standard_unavailable_live_entry_for_new_user_absent_in_snapshot(self):
        mod = _load_runtime()
        data = {'users': {'u_old': {}, 'u_new': {}}}
        meter = mod.PortalMeter(data, threading.RLock(), lambda: None, {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'}})
        meter.live_snapshot = {'users': {'u_old': {'ips': [], 'ok': True, 'hysteria_ok': True, 'reality_ok': True, 'error': ''}}}
        meter.live_sampled_at = time.time()

        s_new = meter.summary('u_new')
        co = s_new['current_online']
        self.assertIn('ips', co, '新建用户未出现在上一轮 live_snapshot 时不得返回缺字段的空字典 {}')
        self.assertFalse(co.get('ok', True))
        self.assertIn('hysteria_ok', co)
        self.assertIn('reality_ok', co)

    def test_read_rejects_non_dict_source_config_with_value_error(self):
        mod = _load_runtime()
        meter = mod.PortalMeter({}, threading.RLock(), lambda: None, {})
        with self.assertRaises(ValueError):
            meter._read('hysteria', 'not-a-dict')
        with self.assertRaises(ValueError):
            meter._read('reality', ['bad'])


if __name__ == '__main__':
    unittest.main()
