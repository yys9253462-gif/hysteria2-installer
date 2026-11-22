"""回归测试：usage-meter-runtime 保存失败嵌套锁死锁根治、summary/hot_summary 坏数据与 NaN 清洗、usage-meter-core 过滤控制字符 sampled_users/baseline_at 及 usage-meter-xray-config 并发复读防符号链接与 fd 清理隔离。"""

import importlib.util
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


core = _load('um_core_b61', 'usage-meter-core-20261007-v1.py')
runtime = _load('um_runtime_b61', 'usage-meter-runtime-20261007-v1.py')
xcfg = _load('um_xcfg_b61', 'usage-meter-xray-config-20261007-v1.py')


class TestUsageMeterRuntimeDeadlockAndXrayCfgGuards(unittest.TestCase):
    def test_runtime_poll_save_failure_does_not_deadlock_on_non_reentrant_lock(self):
        """PortalMeter.poll 在 self.save() 抛异常回滚时，使用普通非可重入 threading.Lock 不得死锁。"""
        lock = threading.Lock()
        data = {'users': {'alice': {'used_bytes': 10, 'status': 'active'}}}
        calls = {'n': 0}

        def failing_save():
            calls['n'] += 1
            raise OSError('disk full')

        meter = runtime.PortalMeter(
            data,
            lock,
            failing_save,
            {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'}},
            read=lambda src, cfg: {'alice': {'tx': 100, 'rx': 200}},
            epoch=lambda svc: 'epoch-1',
        )
        done = threading.Event()
        err = []

        def worker():
            try:
                meter.poll()
            except BaseException as exc:
                err.append(exc)
            finally:
                done.set()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        finished = done.wait(timeout=3.0)
        self.assertTrue(finished, 'PortalMeter.poll 在保存失败回滚路径发生嵌套锁死锁！')
        self.assertEqual(err, [])
        # 保存失败后 used_bytes 应正确回滚为 10
        self.assertEqual(data['users']['alice']['used_bytes'], 10)

    def test_runtime_summary_and_hot_summary_survive_non_dict_data_and_nan_legacy(self):
        """summary / hot_summary 面对非 dict 的 self.data 与 NaN/Inf legacy_auth_value 不得崩溃或输出非有限浮点。"""
        meter = runtime.PortalMeter(
            'corrupt-data',
            threading.RLock(),
            lambda: None,
            {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'}},
        )
        s = meter.summary('alice')
        self.assertIsNone(s['measured_bytes'])
        hs = meter.hot_summary('alice')
        self.assertIsNone(hs['measured_bytes'])

        meter2 = runtime.PortalMeter(
            {'users': {'alice': {'legacy_auth_value': float('nan')}}},
            threading.RLock(),
            lambda: None,
            {'hysteria': {'url': 'http://127.0.0.1:19996', 'secret': 's'}},
        )
        s2 = meter2.summary('alice')
        self.assertIsNone(s2['legacy_auth_value'], 'NaN legacy_auth_value 必须被清洗为 None 防 JSON 序列化失败')

    def test_core_apply_sample_filters_control_chars_in_active_users_sampled_users_and_baseline(self):
        """apply_sample 必须拒绝含控制字符的 active_users，并过滤旧状态里含控制字符的 sampled_users 与 baseline_at。"""
        with self.assertRaises(ValueError):
            core.apply_sample({}, 'hysteria', 'e1', {}, '2026-01-01T00:00:00Z', active_users=['bad\nuid'])

        state = {
            'sources': {
                'hysteria': {
                    'epoch': 'e1',
                    'counters': {'ok': {'tx': 1, 'rx': 1}},
                    'sampled_users': ['ok', 'bad\nuid'],
                    'baseline_at': '2026-01-01\nbad',
                }
            }
        }
        out = core.apply_sample(state, 'hysteria', 'e1', {'ok': {'tx': 2, 'rx': 2}}, '2026-01-02T00:00:00Z')
        self.assertNotIn('bad\nuid', out['deltas'])
        self.assertNotIn('baseline_at', state['sources']['hysteria'])

    def test_xray_config_recheck_uses_regular_reader_and_isolates_fd_close_error(self):
        """enable_iplimit_routing / enable_reality_online 并发复读必须走 _read_regular_config_bytes，且 _write_private_bytes 隔离 os.close 异常。"""
        src = (ROOT / 'usage-meter-xray-config-20261007-v1.py').read_text(encoding='utf-8')
        self.assertNotIn('if path.read_bytes()!=original:', src,
                         '并发变更复读不得绕过 _read_regular_config_bytes')
        self.assertGreaterEqual(src.count('_read_regular_config_bytes(path)[0] != original'), 2)

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'out.json'
            real_open = os.open
            real_close = os.close
            opened_fds = []

            def spy_open(*a, **kw):
                fd = real_open(*a, **kw)
                opened_fds.append(fd)
                return fd

            try:
                with mock.patch.object(xcfg.os, 'open', side_effect=spy_open), \
                     mock.patch.object(xcfg.os, 'fdopen', side_effect=RuntimeError('fdopen-orig')), \
                     mock.patch.object(xcfg.os, 'close', side_effect=OSError('close-boom')):
                    with self.assertRaisesRegex(RuntimeError, 'fdopen-orig'):
                        xcfg._write_private_bytes(target, b'{}', 0o600)
            finally:
                for fd in opened_fds:
                    try:
                        real_close(fd)
                    except OSError:
                        pass


if __name__ == '__main__':
    unittest.main()
