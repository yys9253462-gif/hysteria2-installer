import importlib.util
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class UsageMeterRuntimeAndXrayConfigGuardTests(unittest.TestCase):
    def test_runtime_iso_ts_and_recent_gaps_nan_window_guard(self):
        rt = _load('usage_runtime_b56_6', 'usage-meter-runtime-20261007-v1.py')
        # 允许首尾空白和小写 z
        ts = rt._parse_ts(' 2026-11-22T01:02:03z ')
        self.assertGreater(ts, 0)

        now_iso = datetime.now(timezone.utc).isoformat()
        m = {'gaps': [{'at': now_iso, 'reason': 'restart'}]}
        # 非有限 window_seconds（如 NaN / bool）不得让近期缺口被静默抹除
        recent_nan = rt._recent_gaps(m, window_seconds=float('nan'))
        recent_bool = rt._recent_gaps(m, window_seconds=True)
        self.assertEqual(len(recent_nan), 1)
        self.assertEqual(len(recent_bool), 1)

    def test_runtime_summary_and_hot_summary_handle_unhashable_uid(self):
        rt = _load('usage_runtime_b56_6_uid', 'usage-meter-runtime-20261007-v1.py')
        data = {'users': {'alice': {'used_bytes': 10}}, 'usage_meter': {}}
        meter = rt.PortalMeter(data, threading.RLock(), lambda: None, {'hysteria': {'url': 'http://127.0.0.1:9', 'secret': 's'}})
        s = meter.summary(['unhashable'])
        hs = meter.hot_summary({'unhashable': 1})
        self.assertIsNone(s['measured_bytes'])
        self.assertFalse(s['measurement_ok'])
        self.assertIsNone(hs['measured_bytes'])
        self.assertFalse(hs['measurement_ok'])

    def test_runtime_configured_sources_rejects_dash_or_ctrl_binary_and_from_file_bounds_size(self):
        rt = _load('usage_runtime_b56_6_cfg', 'usage-meter-runtime-20261007-v1.py')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # 即使存在以 '-' 开头的文件，也不应把以 '-' 开头的 binary 当作合法配置放行
            dash_file = td_path / '-fake-xray'
            dash_file.write_text('x', encoding='utf-8')
            old_cwd = __import__('os').getcwd()
            __import__('os').chdir(td)
            try:
                meter = rt.PortalMeter(
                    {}, threading.RLock(), lambda: None,
                    {'reality': {'binary': '-fake-xray', 'address': '127.0.0.1:10085'}},
                )
                self.assertEqual(meter.configured_sources(), [])
            finally:
                __import__('os').chdir(old_cwd)

            huge_cfg = td_path / 'huge.json'
            huge_cfg.write_bytes(b' ' * (2 * 1024 * 1024 + 16))
            with self.assertRaises(ValueError):
                rt.from_file({}, threading.RLock(), lambda: None, huge_cfg)

    def test_xray_config_rejects_nan_payload_before_writing_candidate(self):
        xc = _load('usage_xray_cfg_b56_6', 'usage-meter-xray-config-20261007-v1.py')
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text(
                '{"api": {"tag": "usage-meter-api", "services": ["StatsService"]}, '
                '"inbounds": [], "outbounds": [{"protocol": "freedom", "tag": "direct"}], '
                '"extra_bad": NaN}',
                encoding='utf-8',
            )
            with self.assertRaises(ValueError):
                xc.enable_iplimit_routing(str(cfg_path), '/usr/local/bin/xray', '127.0.0.1:10085')
            with self.assertRaises(ValueError):
                xc.enable_reality_online(str(cfg_path), '/usr/local/bin/xray', '127.0.0.1:10085')


if __name__ == '__main__':
    unittest.main()
