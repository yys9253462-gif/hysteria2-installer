"""proxy_services 容器或单条记录损坏时，gost 配置生成与增删不能整体失败。

旧行为：`for ... in data.get('proxy_services', [])` 在容器是 null/str/int 时抛
TypeError，`svc.get(...)` 在条目是字符串时抛 AttributeError，端口写成 "abc"
时抛 ValueError —— 都被 reload_gost 吞成 `False`，界面只显示
「GOST 配置未成功应用」，新增代理永久失败。
"""
import ast
import copy
import json
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def load_writer():
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
              and n.name == 'write_gost_config')
    ready = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
                 and n.name == 'gost_ports_ready')
    helper = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                  and n.name == 'proxy_services')
    root = Path(__file__).resolve().parents[1] / 'tests' / '_gost_fixture'
    env = {}
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in (
                'PRIVATE_REJECT_RULES', 'GOST_PRIVATE_BYPASS') for t in n.targets):
            exec(compile(ast.Module(body=[copy.deepcopy(n)], type_ignores=[]), '<const>', 'exec'), env)
    env['gost_written_ports'] = []
    env['sys'] = __import__('sys')
    exec(compile(ast.Module(body=[copy.deepcopy(helper), copy.deepcopy(fn), copy.deepcopy(ready)], type_ignores=[]),
                 '<gost>', 'exec'), env)
    return env


class GostConfigCorruptStateTests(unittest.TestCase):
    def test_corrupt_entries_are_skipped_not_fatal(self):
        for bad in (None, 'x', 7, [None], ['x'], [7], [{'port': 'abc'}],
                    [{'port': True}], [{'port': None}], [{'port': -1}],
                    [{'port': 70000}], [{'type': None, 'port': 7000}]):
            with self.subTest(bad=bad):
                import tempfile
                root = Path(tempfile.mkdtemp())
                written = {}
                env = load_writer()
                env.update({'data': {'proxy_services': bad}, 'data_lock': threading.RLock(),
                            'portal_path': root / 'portal.json', 'json': json,
                            'atomic_write_private': lambda p, b: written.update(
                                path=p, payload=b)})
                env['write_gost_config']()
                self.assertIn('path', written)
                cfg = json.loads(written['payload'])
                # 损坏条目一律跳过；合法端口必须保留。
                ports = [s['addr'] for s in cfg['services']]
                self.assertNotIn(':-1', ports)
                self.assertNotIn(':70000', ports)

    def test_valid_entries_still_written(self):
        import tempfile
        from unittest.mock import patch
        root = Path(tempfile.mkdtemp())
        written = {}
        env = load_writer()
        env.update({'data': {'proxy_services': [
            {'type': 'socks5', 'port': 25001, 'username': 'u', 'password': 'p'},
            {'type': 'http', 'port': 25002, 'username': 'u2', 'password': 'p2'},
            'broken']},
            'data_lock': threading.RLock(), 'portal_path': root / 'portal.json',
            'json': json,
            'atomic_write_private': lambda p, b: written.update(payload=b)})
        env['write_gost_config']()
        cfg = json.loads(written['payload'])
        self.assertEqual([s['addr'] for s in cfg['services']], [':25001', ':25002'])
        self.assertEqual(cfg['services'][0]['handler']['type'], 'socks5')
        self.assertEqual(cfg['services'][1]['handler']['type'], 'http')

    def test_every_service_refuses_private_destinations(self):
        """代理不能当跳板访问内网、云元数据和本机端口（2026-11-03 修）。

        生成的配置在 SE 上喂给真 gost 3.2.6 验证过：带 bypass 时
        127.0.0.1 / localhost 被拒，example.com 照常 200。
        """
        import ipaddress
        import tempfile
        written = {}
        env = load_writer()
        env.update({'data': {'proxy_services': [
            {'type': 'socks5', 'port': 25001}, {'type': 'http', 'port': 25002}]},
            'data_lock': threading.RLock(), 'portal_path': Path(tempfile.mkdtemp()) / 'portal.json',
            'json': json, 'atomic_write_private': lambda p, b: written.update(payload=b)})
        env['write_gost_config']()
        cfg = json.loads(written['payload'])
        bypasses = {b['name']: b['matchers'] for b in cfg.get('bypasses', [])}
        for svc in cfg['services']:
            with self.subTest(addr=svc['addr']):
                matchers = bypasses.get(svc.get('bypass'), [])
                nets = [ipaddress.ip_network(m) for m in matchers if '/' in m]
                for target in ('127.0.0.1', '169.254.169.254', '10.1.2.3', '192.168.1.1', '::1'):
                    addr = ipaddress.ip_address(target)
                    self.assertTrue(any(addr in n for n in nets if n.version == addr.version), target)
                self.assertIn('localhost', matchers)


    def setup_env(self, services, tls=None):
        import tempfile
        written = {}
        env = load_writer()
        env.update({'data': {'proxy_services': services}, 'data_lock': threading.RLock(),
                    'portal_path': Path(tempfile.mkdtemp()) / 'portal.json', 'json': json,
                    'atomic_write_private': lambda p, b: written.update(payload=b),
                    'gost_tls_paths': tls or (lambda root: ('/c.pem', '/k.pem'))})
        return env, written

    def test_readiness_only_waits_for_ports_actually_written(self):
        """坏端口没写进 gost.yml，就不能拿它判定「未生效」（2026-11-03 修）。

        旧实现 gost_ports_ready 自己解析：True 当成 1、70000 照收，gost 永远不会
        监听这些端口，每次增删代理都被判失败并回滚。
        """
        env, _ = self.setup_env([{'type': 'socks5', 'port': 25001}, {'port': True}, {'port': 70000}])
        env['write_gost_config']()
        env['_listening_ports_detail'] = lambda: ({25001}, True)
        self.assertTrue(env['gost_ports_ready']())
        env['_listening_ports_detail'] = lambda: (set(), True)
        self.assertFalse(env['gost_ports_ready']())

if __name__ == '__main__':
    unittest.main()
