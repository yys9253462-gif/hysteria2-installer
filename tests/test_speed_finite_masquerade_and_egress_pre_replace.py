"""回归测试：/traffic-speed 非有限/负速率过滤、read_masquerade_port 坏编码与纯 ASCII 端口及 apply_egress_config 替换前失败不误回滚重启。"""
import ast
import copy
import json
import math
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def _extract_traffic_speed(data, speed_tracker):
    tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
    fn_node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == '_h_get_traffic_speed'
    )
    env = dict(
        portal.__dict__,
        data=data,
        data_lock=threading.RLock(),
        speed_tracker=speed_tracker,
        SPEED_WINDOW_SECONDS=15,
        usage_hot_summary=lambda uid: {
            'measured_bytes': 0,
            'measurement_ok': True,
            'measurement_started_at': None,
            'measurement_scope': 'since_measurement_started',
        },
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(fn_node)], type_ignores=[])),
                 '<speed-finite-test>', 'exec'), env)
    return env['_h_get_traffic_speed']


class SpeedFiniteMasqueradeAndEgressPreReplaceTests(unittest.TestCase):
    def test_traffic_speed_ignores_nan_inf_and_negative_samples(self):
        """/traffic-speed 必须过滤 NaN、Inf 与负速率样本，确保输出严格合法的有限 JSON 数值。"""
        now_m = 500.0
        data = {'users': {'u1': {'used_bytes': 10}, 'u2': {'used_bytes': 20}}}
        tracker = {
            'u1': {
                'hysteria': (now_m - 1.0, float('nan'), 100.0),
                'reality': (now_m - 1.0, float('inf'), -50.0),
            },
            'u2': {
                'hysteria': (now_m - 1.0, 12.5, 25.0),
            },
        }
        fn = _extract_traffic_speed(data, tracker)
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            reply_json=lambda code, payload: (code, payload),
        )
        with patch.object(time, 'monotonic', return_value=now_m):
            code, payload = fn(handler, '')
        self.assertEqual(code, 200)
        # 严格 JSON 序列化必须成功（allow_nan=False 会对 NaN/Infinity 抛 ValueError）
        serialized = json.dumps(payload, allow_nan=False)
        self.assertIn('"ok": true', serialized)
        self.assertTrue(math.isfinite(payload['node_tx']))
        self.assertTrue(math.isfinite(payload['node_rx']))
        self.assertEqual(payload['node_tx'], 12.5)
        self.assertEqual(payload['node_rx'], 25.0)
        self.assertEqual(payload['users']['u1']['tx'], 0.0)
        self.assertEqual(payload['users']['u1']['rx'], 0.0)

    def test_read_masquerade_port_survives_invalid_utf8_and_rejects_fullwidth_digits(self):
        """config.yaml 含非 UTF-8 字节时不抛 UnicodeDecodeError，全角数字端口返回 None。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_bytes(b'\xff\xfeinvalid\nlistenHTTPS: :11690\n')
            self.assertIsNone(portal.read_masquerade_port(str(cfg)))

            cfg.write_text('masquerade:\n  listenHTTPS: :\uff11\uff11\uff16\uff19\uff10\n', encoding='utf-8')
            self.assertIsNone(portal.read_masquerade_port(str(cfg)))

    def test_apply_egress_config_skips_rollback_restart_when_failure_happens_before_replace(self):
        """若在 os.replace 替换 config.yaml 之前写盘失败，原配置未改动，不应误触发 _rollback_outbounds 重启服务。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'config.yaml'
            cfg.write_text('listen: :443\noutbounds:\n  - name: direct_ipv4\n    type: direct\n', encoding='utf-8')
            data = {'warp_enabled': True, 'warp_rules': ['openai.com'], 'custom_outbounds': [], 'outbound_mode': 'rules'}
            rollback_mock = Mock(return_value='active')
            with patch.object(portal, '_hy2_runtime_identity', return_value=('active', '100', 't1')), \
                    patch.object(portal, '_hy2_config_loaded', return_value=False), \
                    patch.object(portal.tempfile, 'mkstemp', side_effect=OSError('disk full')), \
                    patch.object(portal, '_rollback_outbounds', rollback_mock):
                ok, err = portal.apply_egress_config(data, threading.RLock(), config_path=str(cfg))
            self.assertFalse(ok)
            self.assertIn('disk full', err)
            rollback_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
