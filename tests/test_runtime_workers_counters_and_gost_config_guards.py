"""回归测试：节点流量计数读取容错、速率采样有限性、在线 IP 快照类型安全、Reality 限流配置容错与 GOST 凭据净化。"""

import ast
import json
import math
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _load_serve_nested(name, extra_ns):
    """提取 serve() 内部嵌套函数并在受控命名空间中编译返回。"""
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'serve':
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef) and sub.name == name:
                    src = ast.get_source_segment(PORTAL_SRC, sub)
                    dedented = '\n'.join(
                        line[4:] if line.startswith('    ') else line
                        for line in src.splitlines()
                    )
                    ns = {'math': math, 'time': time, 'json': json, 'Path': Path}
                    ns.update(extra_ns)
                    exec(dedented, ns)
                    return ns[name]
    raise AssertionError(f'未在 serve() 中找到 {name}')


class RuntimeWorkersCountersAndGostConfigGuardsTests(unittest.TestCase):
    def test_node_traffic_counters_handles_unreadable_proc_net_dev(self):
        """/proc/net/dev 不可读时 node_traffic_counters 不得抛 OSError 导致接口 500。"""
        def fake_open(*args, **kwargs):
            raise OSError('proc unavailable')

        fn = _load_serve_nested('node_traffic_counters', {
            'node_default_ifaces': lambda: ['eth0'],
            'open': fake_open,
        })
        res = fn()
        self.assertEqual(res['rx_bytes'], 0)
        self.assertEqual(res['tx_bytes'], 0)
        self.assertEqual(res['interfaces'], [])
        self.assertIn('boot_id', res)

    def test_meter_speed_sample_rejects_nan_inf_bool_and_negative_values(self):
        """_meter_speed_sample 必须拒绝 nan/inf/bool/负数，防止污染实时速率快照。"""
        tracker = {}
        fn = _load_serve_nested('_meter_speed_sample', {
            'data_lock': threading.Lock(),
            'speed_tracker': tracker,
        })
        bad_cases = [
            (float('nan'), 100, 5),
            (100, float('inf'), 5),
            (100, 100, float('nan')),
            (100, 100, float('inf')),
            (-10, 100, 5),
            (100, -1, 5),
            (True, 100, 5),
            (100, False, 5),
            (100, 100, True),
            ('100', 100, 5),
            (100, 100, 0),
        ]
        for tx, rx, elapsed in bad_cases:
            fn('u1', tx, rx, elapsed, 'hy2')
        self.assertEqual(tracker, {}, '非法采样值不得写入 speed_tracker')

        fn('u1', 500, 1000, 5, 'hy2')
        self.assertIn('hy2', tracker.get('u1', {}))
        _, tx_rate, rx_rate = tracker['u1']['hy2']
        self.assertAlmostEqual(tx_rate, 100.0)
        self.assertAlmostEqual(rx_rate, 200.0)

    def test_live_online_ips_survives_corrupt_snapshot_and_non_numeric_sampled_at(self):
        """live_online_ips 面对损坏快照、非数字 sampled_at 或脏 ips 元素不得崩溃。"""
        class FakeMeter:
            def __init__(self, snapshot, sampled_at):
                self.live_snapshot = snapshot
                self.live_sampled_at = sampled_at

        now = time.time()
        cases = [
            ('not-a-dict', now),
            ({'users': 'broken'}, now),
            ({'users': {'u1': 'broken'}}, now),
            ({'users': {'u1': {'hysteria_ok': True, 'ips': 'not-a-list'}}}, now),
            ({'users': {'u1': {'hysteria_ok': True, 'ips': [None, 123, {'ip': 456}]}}}, now),
            ({'users': {'u1': {'hysteria_ok': True, 'ips': [{'ip': '1.2.3.4'}]}}}, None),
            ({'users': {'u1': {'hysteria_ok': True, 'ips': [{'ip': '1.2.3.4'}]}}}, 'bad'),
            ({'users': {'u1': {'hysteria_ok': True, 'ips': [{'ip': '1.2.3.4'}]}}}, True),
            ({'users': {'u1': {'hysteria_ok': True, 'ips': [{'ip': '1.2.3.4'}]}}}, float('nan')),
        ]
        for snap, sampled_at in cases:
            fn = _load_serve_nested('live_online_ips', {'usage_meter': FakeMeter(snap, sampled_at)})
            self.assertEqual(fn('u1'), set(), f'损坏快照 {(snap, sampled_at)!r} 应安全返回空集')

        ok_snap = {'users': {'u1': {'hysteria_ok': True, 'ips': [None, {'ip': 123}, {'ip': '1.2.3.4'}]}}}
        fn_ok = _load_serve_nested('live_online_ips', {'usage_meter': FakeMeter(ok_snap, now)})
        self.assertEqual(fn_ok('u1'), {'1.2.3.4'})

    def test_reality_iplimit_worker_guards_corrupt_cfg_and_missing_module_spec(self):
        """reality_iplimit_worker 必须隔离坏配置 JSON 并检查模块 spec 非空。"""
        start = PORTAL_SRC.index('    def reality_iplimit_worker():')
        end = PORTAL_SRC.index('    def usage_summary(uid):', start)
        body = PORTAL_SRC[start:end]
        self.assertIn('cfg_path.is_file()', body, '读取 usage-meter-config.json 前应确认是普通文件')
        self.assertIn('except (OSError, ValueError):', body, '损坏的 usage-meter-config.json 应原地容错而非炸出整轮循环')
        self.assertIn('if spec is None or spec.loader is None:', body, '缺失限流配置脚本时应显式报错而非 AttributeError')

    def test_write_gost_config_rejects_float_port_and_coerces_non_string_credentials(self):
        """write_gost_config 必须拒绝小数端口并把非字符串账号密码净化为空串。"""
        written = {}

        def fake_atomic_write(path, payload):
            written['cfg'] = json.loads(payload.decode('utf-8'))

        gost_ports = []
        with tempfile.TemporaryDirectory() as td:
            data = {
                'proxy_services': [
                    {'type': 'socks5', 'port': 1080.9, 'username': 'u', 'password': 'p'},
                    {'type': 'socks5', 'port': 1081, 'username': 123, 'password': None},
                    {'type': 'http', 'port': '8080', 'username': 'alice', 'password': 'secret'},
                ],
            }
            fn = _load_serve_nested('write_gost_config', {
                'portal_path': Path(td) / 'portal.json',
                'data_lock': threading.Lock(),
                'data': data,
                'proxy_services': portal.proxy_services,
                '_valid_port': portal._valid_port,
                'GOST_PRIVATE_BYPASS': portal.GOST_PRIVATE_BYPASS,
                'PRIVATE_REJECT_RULES': portal.PRIVATE_REJECT_RULES,
                'gost_written_ports': gost_ports,
                'atomic_write_private': fake_atomic_write,
                'gost_tls_paths': portal.gost_tls_paths,
            })
            fn()

        self.assertEqual(gost_ports, [1081, 8080], '小数端口 1080.9 必须被拒绝')
        services = written['cfg']['services']
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]['handler']['auth'], {'username': '', 'password': ''})
        self.assertEqual(services[1]['handler']['auth'], {'username': 'alice', 'password': 'secret'})


if __name__ == '__main__':
    unittest.main()
