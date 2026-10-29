"""GitHub 返回非列表（限流对象）时，版本检查必须当成「未知」而不是每轮重跑。

`/contents/?ref=main` 在限流或出错时返回 `{"message": "API rate limit exceeded"}`。
旧写法直接 `for it in items` 抛 TypeError，虽然被 except 兜住不至于 500，
但缓存永远写不进去 —— 面板每次打开都再打一次已限流的接口。
"""
import ast
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def load():
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
              and n.name == '_remote_root_shas')
    cache = {'t': 0.0, 'data': None}
    import urllib.request as request_module
    env = {'time': __import__('time'), 'json': json,
           'urllib': type('U', (), {'request': request_module}),
           'AWG_REPO': 'owner/repo', '_ver_cache': cache,
           '_log_ignored': lambda *a: None}
    exec(compile(ast.Module(body=[copy.deepcopy(fn)], type_ignores=[]),
                 '<remote-shas>', 'exec'), env)
    return env, cache


class Response:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self._payload).encode()


class VersionListingPayloadTests(unittest.TestCase):
    def call(self, payload):
        env, cache = load()
        with patch.object(env['urllib'].request, 'urlopen', return_value=Response(payload)):
            return env['_remote_root_shas'](), cache

    def test_rate_limit_object_is_not_cached(self):
        for payload in ({'message': 'API rate limit exceeded'}, 'oops', 7, None):
            with self.subTest(payload=payload):
                shas, cache = self.call(payload)
                self.assertIsNone(shas)
                self.assertIsNone(cache['data'])

    def test_valid_listing_is_cached(self):
        payload = [{'name': 'portal.py', 'sha': 'a' * 40}, {'name': 'x', 'sha': 'b' * 40}]
        shas, cache = self.call(payload)
        self.assertEqual(shas, {'portal.py': 'a' * 40, 'x': 'b' * 40})
        self.assertEqual(cache['data'], shas)

    def test_entries_without_name_are_ignored(self):
        payload = [None, {'sha': 'a' * 40}, {'name': 'portal.py', 'sha': 'b' * 40}]
        shas, _ = self.call(payload)
        self.assertEqual(shas, {'portal.py': 'b' * 40})


if __name__ == '__main__':
    unittest.main()
