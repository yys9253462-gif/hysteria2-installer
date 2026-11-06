"""GitHub 版本检查失败也要短暂缓存（2026-11-06 修）。

旧实现失败不写缓存，check-version 每次调用两遍：限流后每次页面加载都再打两次 GitHub。
摘出真实的 _remote_root_shas 闭包，urlopen 打桩成 HTTP 403。
"""
import ast
import copy
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def load(env):
    tree = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_remote_root_shas')
    exec(compile(ast.Module(body=[copy.deepcopy(node)], type_ignores=[]), '<shas>', 'exec'), env)
    return env['_remote_root_shas']


class VersionCheckCacheTests(unittest.TestCase):
    def test_failures_are_cached_briefly(self):
        calls = []

        def urlopen(*a, **k):
            calls.append(1)
            raise urllib.error.HTTPError('u', 403, 'rate limited', {}, None)
        clock = {'t': 1000.0}
        env = dict(portal.__dict__, _ver_cache={'t': 0.0, 'data': None}, _log_ignored=lambda *a: None,
                   time=mock.Mock(time=lambda: clock['t']),
                   urllib=mock.Mock(request=mock.Mock(Request=lambda *a, **k: None, urlopen=urlopen)))
        fn = load(env)
        for _ in range(5):
            self.assertIsNone(fn())
        self.assertEqual(len(calls), 1, '失败后没有缓存，每次都重新请求 GitHub')
        clock['t'] += 61
        fn()
        self.assertEqual(len(calls), 2, '失败缓存过期后应重试')


if __name__ == '__main__':
    unittest.main()
