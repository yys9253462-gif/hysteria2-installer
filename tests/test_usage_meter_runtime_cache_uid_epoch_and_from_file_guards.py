"""回归测试：usage-meter-runtime-20261007-v1.py 的 max_age 守卫、_recent_gaps 防缓存污染、poll 脏用户键/坏 epoch 隔离、legacy 清洗及 from_file 防符号链接。"""

import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATH = ROOT / 'usage-meter-runtime-20261007-v1.py'


def _load_runtime():
    spec = importlib.util.spec_from_file_location('usage_meter_runtime_guard_test', RUNTIME_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterRuntimeCacheUidEpochAndFromFileGuardsTests(unittest.TestCase):
    def setUp(self):
        self.rt = _load_runtime()

    def test_source_fresh_sanitizes_invalid_max_age(self):
        """_source_fresh 面对非有限、布尔、非正或字符串 max_age 不得抛异常或误判。"""
        now_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        health = {'hysteria': {'ok': True, 'sampled_at': now_iso}}
        for bad_age in (True, False, 0, -10, float('nan'), float('inf'), 'bad', None):
            with self.subTest(bad_age=bad_age):
                self.assertTrue(self.rt._source_fresh(health, 'hysteria', max_age=bad_age))

    def test_recent_gaps_handles_non_dict_and_isolates_cached_dicts(self):
        """_recent_gaps 遇到非 dict 容器不得抛 AttributeError，且修改返回列表中的字典不得污染全局缓存。"""
        for bad_m in (None, [], 'corrupt', 123):
            with self.subTest(bad_m=bad_m):
                res = self.rt._recent_gaps(bad_m)
                self.assertTrue(isinstance(res, list) and len(res) >= 1)

        now_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        m = {'gaps': [{'at': now_iso, 'reason': 'restart'}]}
        first = self.rt._recent_gaps(m)
        self.assertEqual(first[0]['reason'], 'restart')
        first[0]['reason'] = 'POISONED'
        second = self.rt._recent_gaps(m)
        self.assertEqual(second[0]['reason'], 'restart', '调用方修改返回值不得污染全局 _recent_gaps_cache')

    def test_poll_isolates_empty_or_non_str_uid_cleans_legacy_and_validates_epoch(self):
        """poll 遇到空串/非串 uid 不得整批回滚正常用户，legacy_auth_value 须清洗脏值，空/脏 epoch 须在锁外拦截。"""
        data = {
            'users': {
                '': {'used_bytes': 10},
                123: {'used_bytes': 20},
                'alice': {'used_bytes': 'corrupt_legacy'},
            },
        }
        lock = threading.RLock()
        saved = []
        meter = self.rt.PortalMeter(
            data,
            lock,
            lambda: saved.append(True),
            {'hysteria': {'url': 'http://127.0.0.1:9999', 'secret': 's'}},
            read=lambda src, cfg: {'alice': {'tx': 100, 'rx': 200}},
            epoch=lambda svc: 'ep-1',
        )
        # 首轮建立基线，第二轮累加
        meter.poll()
        self.assertNotIn('hysteria', meter.failed_sources, '脏 uid 键不应让合法用户采样失败')
        self.assertEqual(data['users']['alice']['legacy_auth_value'], 0, '损坏的旧 used_bytes 不得原样写入 legacy_auth_value')

        meter.read = lambda src, cfg: {'alice': {'tx': 150, 'rx': 250}}
        meter.poll()
        self.assertEqual(data['users']['alice']['used_bytes'], 100)

        # 空串 / 含换行 epoch 必须在调用 self.read 前拦截，标记来源失败
        read_called = []
        bad_meter = self.rt.PortalMeter(
            {'users': {'alice': {'used_bytes': 0}}},
            threading.RLock(),
            lambda: None,
            {'hysteria': {'url': 'http://127.0.0.1:9999', 'secret': 's'}},
            read=lambda src, cfg: read_called.append(True) or {},
            epoch=lambda svc: 'bad\nepoch',
        )
        bad_meter.poll()
        self.assertIn('hysteria', bad_meter.failed_sources)
        self.assertEqual(read_called, [], '非法 epoch 应在调用 read() 前就拦截')

    def test_poll_handles_non_dict_data_in_except_and_measurement_total_rejects_empty_uid(self):
        """self.data 异常变为非 dict 时 poll 不得二次抛 AttributeError；_measurement_total 须拒绝空串 uid。"""
        m = self.rt.PortalMeter(
            'broken-data',
            threading.RLock(),
            lambda: None,
            {'hysteria': {'url': 'http://127.0.0.1:9999', 'secret': 's'}},
            read=lambda src, cfg: {},
            epoch=lambda svc: 'ep-1',
        )
        # 不应向外抛 AttributeError
        m.poll()
        self.assertIn('hysteria', m.failed_sources)

        meter_dict = {
            'sources': {'hysteria': {'epoch': 'ep-1', 'counters': {}}},
            'totals': {'': {'tx': 1, 'rx': 2}},
        }
        self.assertIsNone(self.rt._measurement_total(meter_dict, ['hysteria'], ''))

    def test_from_file_rejects_directory_and_symlink(self):
        """from_file 须使用 lstat 拒绝目录与符号链接配置文件。"""
        src = RUNTIME_PATH.read_text(encoding='utf-8')
        from_file_part = src[src.index('def from_file('):]
        self.assertIn('lstat', from_file_part)
        self.assertIn('S_ISREG', from_file_part)

        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / 'as_dir'
            d.mkdir()
            with self.assertRaises(ValueError):
                self.rt.from_file({}, threading.RLock(), lambda: None, d)

            real = Path(td) / 'real.json'
            real.write_text(json.dumps({'hysteria': {'url': 'http://127.0.0.1:1', 'secret': 's'}}), encoding='utf-8')
            link = Path(td) / 'link.json'
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(ValueError):
                    self.rt.from_file({}, threading.RLock(), lambda: None, link)


if __name__ == '__main__':
    unittest.main()
