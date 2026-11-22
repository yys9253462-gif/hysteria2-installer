import ast
import importlib.util
import json
import math
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'


def _load_portal_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('portal_batch56_item3', PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_handler_method(method_name):
    tree = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))
    serve_fn = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == 'serve'
    )
    for node in ast.walk(serve_fn):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return ast.unparse(item)
    raise AssertionError(f'未找到处理器方法: {method_name}')


def _extract_serve_def(func_name):
    tree = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))
    serve_fn = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == 'serve'
    )
    for node in serve_fn.body:
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return ast.unparse(node)
    raise AssertionError(f'未找到 serve 内函数: {func_name}')


class UpdateRefIpDenyAuthSaveAndIplimitGuardTests(unittest.TestCase):
    def test_resolve_update_ref_rejects_non_str_and_falls_back_on_null_sha(self):
        mod = _load_portal_module()
        with self.assertRaises(ValueError):
            mod.resolve_update_ref(None)
        with self.assertRaises(ValueError):
            mod.resolve_update_ref(12345)

        good_sha = 'a' * 40
        calls = []

        class FakeResp:
            def __init__(self, body):
                self._body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit=-1):
                return self._body

        def fake_urlopen(req, timeout=8):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            calls.append(url)
            if 'api.github.com' in url:
                # GitHub API 返回 {"sha": null}，旧实现会在这里抛 TypeError 跳过 atom 兜底
                return FakeResp(b'{"sha": null}')
            return FakeResp(f'<link href="/owner/repo/commit/{good_sha}"/>'.encode('utf-8'))

        orig_urlopen = mod.urllib.request.urlopen
        mod.urllib.request.urlopen = fake_urlopen
        try:
            resolved = mod.resolve_update_ref('main')
        finally:
            mod.urllib.request.urlopen = orig_urlopen

        self.assertEqual(resolved, good_sha)
        self.assertEqual(len(calls), 2, f'应回退到 commits/main.atom，实际 calls={calls}')

    def test_parse_ip_deny_rejects_non_str_user_id_ip_and_non_finite_now(self):
        mod = _load_portal_module()
        with self.assertRaises(ValueError):
            mod.parse_ip_deny('not-a-dict', 1000)
        with self.assertRaises(ValueError):
            mod.parse_ip_deny({'user_id': 12345, 'ips': ['1.2.3.4']}, 1000)
        with self.assertRaises(ValueError):
            mod.parse_ip_deny({'user_id': 'alice', 'ips': [16909060]}, 1000)
        with self.assertRaises(ValueError):
            mod.parse_ip_deny({'user_id': 'alice', 'ips': ['1.2.3.4']}, float('nan'))
        with self.assertRaises(ValueError):
            mod.parse_ip_deny({'user_id': 'alice', 'ips': ['1.2.3.4']}, True)

    def test_verify_api_key_rejects_oversized_header_and_whitespace_key(self):
        verify_src = _extract_handler_method('verify_api_key')
        auth_src = _extract_handler_method('is_authenticated')
        ns = {
            'data_lock': threading.Lock(),
            'data': {'api_key': '   ', 'auth_hash': ''},
            'hmac': __import__('hmac'),
            'hashlib': __import__('hashlib'),
            'verify_session': lambda _cookie: False,
        }
        exec(compile(verify_src + '\n\n' + auth_src, str(PORTAL_PATH), 'exec'), ns)

        class DummyHandler:
            def __init__(self, headers):
                self.headers = headers

        # 持久化 api_key 全为空白时必须拒绝
        h_ws = DummyHandler({'Authorization': 'Bearer    '})
        self.assertFalse(ns['verify_api_key'](h_ws))

        # 含换行控制字符的持久化 api_key 必须拒绝
        ns['data']['api_key'] = 'valid\nkey'
        h_ctrl = DummyHandler({'Authorization': 'Bearer valid\nkey'})
        self.assertFalse(ns['verify_api_key'](h_ctrl))

        # 超长 Authorization 头必须拒绝（即使 key 被设成同样超长也拦住）
        long_key = 'k' * 2048
        ns['data']['api_key'] = long_key
        h_long = DummyHandler({'Authorization': 'Bearer ' + long_key})
        self.assertFalse(ns['verify_api_key'](h_long))

        # Authorization 头值为 None 时不应抛 TypeError
        h_none = DummyHandler({'Authorization': None})
        self.assertFalse(ns['verify_api_key'](h_none))
        self.assertFalse(ns['is_authenticated'](h_none))

    def test_prepare_save_payload_scrubs_nan_to_strict_json(self):
        src = _extract_serve_def('_prepare_save_payload')
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'portal.json'
            p.write_text('{}', encoding='utf-8')
            digest = __import__('hashlib').sha256(p.read_bytes()).digest()
            ns = {
                'portal_path': p,
                'disk_state': {'digest': digest},
                'data': {'port': 8443, 'bad_float': float('nan'), 'nested': [float('inf'), 1.5]},
                'hashlib': __import__('hashlib'),
                'json': json,
                'math': math,
                'merge_cli_owned_state': lambda d, disk: None,
            }
            exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
            raw = ns['_prepare_save_payload']().decode('utf-8')
            self.assertNotIn('NaN', raw)
            self.assertNotIn('Infinity', raw)
            parsed = json.loads(raw)
            self.assertIsNone(parsed['bad_float'])
            self.assertEqual(parsed['nested'], [None, 1.5])

    def test_reality_iplimit_worker_skips_nul_binary_without_clearing_state(self):
        src = _extract_serve_def('reality_iplimit_worker')
        sleeps = []

        class StopLoop(BaseException):
            pass

        def fake_sleep(sec):
            sleeps.append(sec)
            if len(sleeps) >= 1 and sec == 5:
                raise SystemExit()
            # 正常 30s 跳过后再走完外层 sleep(5) 退出，用标记区分是否进了 except Exception

        class StrictPath(type(Path())):
            def is_file(self):
                if '\x00' in str(self):
                    raise ValueError('embedded null byte')
                return super().is_file()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'xray.json').write_text('{}', encoding='utf-8')
            (root / 'usage-meter-config.json').write_text(
                json.dumps({'reality': {'binary': '/usr/bin/xray\x00bad', 'address': '127.0.0.1:10085'}}),
                encoding='utf-8',
            )
            snapshot = {'ips': {'u1': {'1.1.1.1'}}, 'at': 100.0}
            iplimit_state = {'u1': {'admitted': {'1.1.1.1'}}}
            calls = []

            def stop_sleep(sec):
                calls.append((sec, snapshot['at'], 'u1' in iplimit_state))
                if sec == 5:
                    raise StopLoop()
                if len(calls) >= 2:
                    raise StopLoop()

            ns = {
                'portal_path': root / 'portal.json',
                'Path': StrictPath,
                '__file__': str(PORTAL_PATH),
                'json': json,
                'time': type('T', (), {'sleep': staticmethod(stop_sleep)})(),
                'data_lock': threading.Lock(),
                'reality_ip_snapshot': snapshot,
                'reality_iplimit_state': iplimit_state,
                'sys': sys,
            }
            exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
            try:
                ns['reality_iplimit_worker']()
            except StopLoop:
                pass
            # 含 NUL 字节的非法 binary 应直接命中 30 秒跳过分支且在进入 sleep(30) 时未清空状态
            self.assertGreaterEqual(len(calls), 1)
            self.assertEqual(calls[0], (30, 100.0, True), f'非法 binary 应保留状态并走 30s 跳过，实际 calls={calls}')


if __name__ == '__main__':
    unittest.main()
