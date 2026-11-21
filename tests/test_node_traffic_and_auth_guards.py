"""回归测试：整机网卡流量采集兼容非 ASCII 与畸形行，/auth 在异常 ip_tracker 与时钟回拨下不崩溃。"""
import ast
import importlib.util
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_nt_auth_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _extract_funcs(names, ns):
    want = set(names)
    nodes = [n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name in want]
    assert len(nodes) == len(want), f'缺少函数: {want - {n.name for n in nodes}}'
    mod = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(mod)
    exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
    return {name: ns[name] for name in names}


class NodeTrafficAndAuthGuardsTests(unittest.TestCase):
    def test_node_traffic_counters_survives_non_ascii_route_and_malformed_dev_line(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'route').write_bytes(
                b'Iface\tDestination\tGateway\n'
                b'veth\xffbad\t00000000\t0100000A\n'
                b'eth0\t00000000\t0100000A\n'
            )
            (root / 'ipv6_route').write_bytes(b'')
            (root / 'dev').write_bytes(
                b'Inter-| Receive\n'
                b'eth0: 100 0 0 0 0 0 0 0 250 0 0 0 0 0 0 0\n'
                b'veth\xffbad: broken-cols\n'
            )
            (root / 'boot_id').write_bytes(b'boot-123\n')

            real_open = open
            mapping = {
                '/proc/net/route': root / 'route',
                '/proc/net/ipv6_route': root / 'ipv6_route',
                '/proc/net/dev': root / 'dev',
            }

            def fake_open(path, *args, **kwargs):
                return real_open(mapping.get(path, path), *args, **kwargs)

            def fake_path(val):
                if str(val) == '/proc/sys/kernel/random/boot_id':
                    return root / 'boot_id'
                return Path(val)

            ns = dict(
                portal.__dict__,
                open=fake_open,
                Path=fake_path,
                _TUNNEL_IFACE_PREFIXES=('lo', 'wg', 'warp', 'awg', 'tun', 'tap', 'docker', 'veth', 'br-', 'virbr'),
            )
            fns = _extract_funcs(('node_default_ifaces', 'node_traffic_counters'), ns)
            out = fns['node_traffic_counters']()
            self.assertEqual(out['rx_bytes'], 100)
            self.assertEqual(out['tx_bytes'], 250)
            self.assertEqual(out['interfaces'], ['eth0'])
            self.assertEqual(out['boot_id'], 'boot-123')

    def test_auth_survives_corrupt_ip_tracker_and_future_timestamp(self):
        payload = json.dumps({'auth': 'pw-secret', 'addr': '203.0.113.5:5555'}).encode('utf-8')
        replies = []
        handler = SimpleNamespace(
            path='/auth',
            client_address=('127.0.0.1', 50000),
            headers={'Content-Length': str(len(payload))},
            rfile=io.BytesIO(payload),
            auth_rate_limited=lambda: False,
            record_auth_failure=lambda: None,
            reply_json=lambda code, body: replies.append((code, body)),
        )
        # 1) ip_tracker[uid] 被改坏成非 dict 时不应抛 AttributeError 阻断合法鉴权
        tracker = {'u1': 'corrupt-tracker'}
        ns = dict(
            portal.__dict__,
            data={'users': {'u1': {'password': 'pw-secret', 'status': 'active', 'ip_limit': 1}}},
            data_lock=threading.RLock(),
            ip_tracker=tracker,
            global_ip_deny={},
            live_online_ips=lambda uid: set(),
            reality_live_ips=lambda uid: set(),
        )
        do_post = _extract_funcs(('do_POST',), ns)['do_POST']
        do_post(handler)
        self.assertEqual(replies[-1], (200, {'ok': True, 'id': 'u1'}))
        self.assertIsInstance(tracker['u1'], dict)

        # 2) 时钟回拨残留的未来时间戳条目应被视为过期而非永久占满 ip_limit=1 名额
        tracker['u1'] = {'198.51.100.9': portal.time.time() + 3600}
        handler.rfile = io.BytesIO(payload)
        do_post(handler)
        self.assertEqual(replies[-1], (200, {'ok': True, 'id': 'u1'}),
                         '未来时间戳残留条目不应永久占满设备上限')


if __name__ == '__main__':
    unittest.main()
