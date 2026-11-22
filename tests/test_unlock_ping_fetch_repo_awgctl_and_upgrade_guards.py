import ast
import http.client
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'


def _load_portal_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('portal_batch56_item10', PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class UnlockPingFetchRepoAwgctlAndUpgradeGuardTests(unittest.TestCase):
    def test_unlock_read_truncates_oversized_incomplete_read_partial(self):
        mod = _load_portal_module()

        class BoomResp:
            def read(self, limit):
                raise http.client.IncompleteRead(b'x' * (limit * 5))

        text = mod._unlock_read(BoomResp(), 128)
        self.assertEqual(len(text), 128)
        self.assertEqual(mod._unlock_read(BoomResp(), 0), '')

    def test_ping_one_rejects_flag_like_or_ctrl_host_and_uses_double_dash(self):
        src = _extract_handler_method('_ping_one')
        seen_cmds = []

        class FakeProc:
            stdout = '0% packet loss\nrtt min/avg/max/mdev = 1.0/2.5/4.0/0.5 ms\n'

        def fake_run(cmd, **kwargs):
            seen_cmds.append(cmd)
            return FakeProc()

        ns = {
            'subprocess': type('S', (), {'run': staticmethod(fake_run)})(),
            'os': __import__('os'),
            're': __import__('re'),
            'math': __import__('math'),
        }
        exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
        fn = ns['_ping_one']

        self.assertEqual(fn(object(), '-c'), (None, None))
        self.assertEqual(fn(object(), '1.1.1.1\n-bad'), (None, None))
        self.assertEqual(seen_cmds, [], f'非法 host 不应拉起 ping，实际={seen_cmds}')

        avg, loss = fn(object(), '1.1.1.1')
        self.assertEqual((avg, loss), (2.5, 0.0))
        self.assertEqual(seen_cmds[0][-2:], ['--', '1.1.1.1'])

    def test_fetch_repo_file_and_remote_blob_sha_reject_traversal_or_query_injection(self):
        src_fetch = _extract_serve_def('_fetch_repo_file')
        src_sha = _extract_serve_def('_remote_blob_sha')
        called = []

        def fail_urlopen(*args, **kwargs):
            called.append(args)
            raise AssertionError('非法参数不得发起任何网络请求')

        ns = {
            're': __import__('re'),
            'AWG_REPO': 'example/repo',
            'urllib': type('U', (), {
                'request': type('R', (), {
                    'Request': staticmethod(lambda url, headers=None: url),
                    'urlopen': staticmethod(fail_urlopen),
                })(),
            })(),
            'json': __import__('json'),
            '_log_ignored': lambda *a: None,
            '_git_blob_sha': lambda b: '',
        }
        exec(compile(src_fetch + '\n\n' + src_sha, str(PORTAL_PATH), 'exec'), ns)

        for bad_name in ('../secret', 'a?b=1', 'a#frag', 'a b', '', '/etc/passwd'):
            with self.subTest(bad_name=bad_name):
                with self.assertRaises(ValueError):
                    ns['_fetch_repo_file'](bad_name)
                self.assertIsNone(ns['_remote_blob_sha'](bad_name))
        self.assertIsNone(ns['_remote_blob_sha']('portal.py', ref='main&evil=1'))
        self.assertEqual(called, [])

    def test_do_upgrade_reality_online_checks_missing_module_spec(self):
        src = _extract_handler_method('_h_post_do_upgrade_impl')
        self.assertIn('spec is None or spec.loader is None', src)

    def test_ensure_awgctl_guards_fd_cleanup_in_finally(self):
        src = _extract_serve_def('ensure_awgctl')
        self.assertIn('if fd is not None:', src)


if __name__ == '__main__':
    unittest.main()
