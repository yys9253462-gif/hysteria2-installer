"""AWG 的 meta / peers 文件被改坏时，/awg-state 仍要返回可用结构。

这两个 JSON 由 awgctl.sh 写入，也可能被手工编辑或截断。
旧写法 `...get('peers', [])` 后直接 len()/p.get()：peers 是字符串或含非 dict
条目时抛异常，整个端点 500，面板的 AWG 卡片整块空白 —— 看起来像「AWG 没装」。
"""
import ast
import copy
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
META = object()
PEERS = object()


def load():
    # awg_state 读 peers 走 awg_peers（下载路由也用它），两个一起摘出来。
    fns = [n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
           and n.name in ('awg_state', 'awg_peers')]
    env = {'AWG_META_PATH': META, 'AWG_PEERS_PATH': PEERS, 'AWG_CTL': '/nonexistent',
           'AWG_CONF_PATH': '/nonexistent', 'AWG_GO_PATH': '/nonexistent',
           'awg_installed': lambda: False, 'awg_active': lambda: False, 'Path': Path}
    exec(compile(ast.Module(body=copy.deepcopy(fns), type_ignores=[]),
                 '<awg-state>', 'exec'), env)
    return env


def run(meta, peers):
    env = load()
    env['awg_read_json'] = lambda path, default: (
        meta if path is META else (peers if path is PEERS else default))
    return env['awg_state']()


class AwgStateRobustnessTests(unittest.TestCase):
    def test_corrupt_peers_do_not_raise(self):
        for bad in ({'peers': 'x'}, {'peers': 7}, {'peers': [None]},
                    {'peers': ['x']}, {'peers': {'a': 1}}, 'oops', 7, None):
            with self.subTest(bad=bad):
                state = run({}, bad)
                self.assertTrue(state['ok'])
                self.assertEqual(state['peer_count'], 0)
                self.assertEqual(state['peers'], [])

    def test_valid_peers_are_kept_and_corrupt_entries_skipped(self):
        state = run({}, {'peers': [None, 'x', {'name': 'ok', 'address': '10.0.0.2'}]})
        self.assertEqual(state['peer_count'], 1)
        self.assertEqual(state['peers'][0]['name'], 'ok')

    def test_corrupt_meta_falls_back_to_defaults(self):
        for bad in (7, 'x', [None], None):
            with self.subTest(bad=bad):
                state = run(bad, {'peers': []})
                self.assertEqual(state['line'], '3')
                self.assertEqual(state['port'], '')
                self.assertEqual(state['endpoint'], '')

    def test_healthy_meta_round_trips(self):
        state = run({'line': '2', 'port': 2408, 'endpoint': 'example.com:2408'},
                    {'peers': [{'name': 'p1'}]})
        self.assertEqual((state['line'], state['port'], state['endpoint']),
                         ('2', '2408', 'example.com:2408'))
        self.assertEqual(state['peer_count'], 1)


class AwgConfDownloadPeersTests(unittest.TestCase):
    """下载 .conf / 二维码的路由同样要容忍坏的 peers.json（2026-11-03）。

    旧路由直接 `awg_read_json(...).get('peers', [])` 后逐个 `p.get(...)`：
    peers 里一条 null / 字符串就抛 AttributeError，do_GET 没有兜底，
    所有客户端的配置都下载不了。
    """

    def peers(self, doc):
        env = load()
        env['awg_read_json'] = lambda path, default: doc if path is PEERS else default
        return env['awg_peers']()

    def test_corrupt_entries_are_skipped(self):
        self.assertEqual(self.peers({'peers': [None, 'x', 7, {'name': 'phone'}]}),
                         [{'name': 'phone'}])
        for bad in ({'peers': 'x'}, {'peers': None}, 'oops', None, 7):
            with self.subTest(bad=bad):
                self.assertEqual(self.peers(bad), [])

    def test_download_route_serves_valid_peer_despite_corrupt_entries(self):
        """把真实路由分支摘出来执行（awgctl / 网络都是桩），只换 peers.json 的内容。"""
        import io
        import re
        import socket
        import subprocess
        from types import SimpleNamespace
        from urllib.parse import parse_qs
        route = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                     and isinstance(n.test, ast.Compare)
                     and isinstance(n.test.comparators[0], ast.Tuple)
                     and [getattr(e, 'value', None) for e in n.test.comparators[0].elts]
                     == ['awg-conf', 'awg-qr.svg'])
        fn = ast.parse('def route(self, awg_route):\n    pass').body[0]
        fn.body = copy.deepcopy(route.body)
        env = load()
        env.update(
            re=re, socket=socket, subprocess=subprocess, parse_qs=parse_qs,
            VALID_AWG_NAME_RE=re.compile(r'^[A-Za-z0-9_.\-]{1,32}$'),
            awg_installed=lambda: True, ensure_awgctl=lambda: True,
            awg_endpoint_error=lambda endpoint: '',
            awg_err_tail=lambda *a, **kw: 'failed',
            awg_run=lambda args, timeout=0: (0, '[Interface]\nPrivateKey = test-only\n', ''),
            awg_read_json=lambda path, default: (
                {'peers': [None, 'broken', {'name': 'phone', 'endpoint': 'vpn.example.com'}]}
                if path is PEERS else default))
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     '<awg-conf-route>', 'exec'), env)
        sent = {}
        handler = SimpleNamespace(
            path='/tok/awg-conf?name=phone', is_authenticated=lambda: True,
            _extend_deadline=lambda *a, **k: True,
            reply=lambda status, body, *a, **kw: sent.update(status=status, body=body),
            send_response=lambda status: sent.update(status=status),
            send_header=lambda *a: None, end_headers=lambda: None,
            wfile=io.BytesIO(), connection=SimpleNamespace(shutdown=lambda how: None))
        env['route'](handler, 'awg-conf')
        self.assertEqual(sent.get('status'), 200, sent)
        self.assertIn(b'[Interface]', handler.wfile.getvalue())


if __name__ == '__main__':
    unittest.main()
