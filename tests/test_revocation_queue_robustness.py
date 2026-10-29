"""待撤销队列被改坏时，撤销必须继续执行且不能伪造出用户。

真实后果：`_pending_revocations` 被写成数字后 `set(...)` 抛 TypeError，
撤销 worker 每 5 秒重试一次都失败 —— 停用/到期用户在所有协议上继续可用；
写成字符串 `"abc"` 时被拆成 a / b / c 三个不存在的 user_id 写进 Xray。
"""
import ast
import copy
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def load():
    body = []
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'pending_revocations':
            body.append(copy.deepcopy(node))
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == 'USER_ID_RE' for t in node.targets):
            body.append(copy.deepcopy(node))
    env = {'re': re}
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 '<revocation-queue>', 'exec'), env)
    return env


class RevocationQueueTests(unittest.TestCase):
    def test_corrupt_queue_values_are_discarded(self):
        env = load()
        for bad in (None, 7, 'abc', {'x': 1}, True):
            with self.subTest(bad=bad):
                self.assertEqual(env['pending_revocations']({'_pending_revocations': bad}), set())

    def test_only_valid_user_ids_survive(self):
        env = load()
        raw = ['good-user', 'also.ok_1', 'bad id', '', 7, None, 'x' * 65, 'a/b']
        self.assertEqual(env['pending_revocations']({'_pending_revocations': raw}),
                         {'good-user', 'also.ok_1'})

    def test_healthy_queue_and_missing_data(self):
        env = load()
        self.assertEqual(env['pending_revocations']({}), set())
        self.assertEqual(env['pending_revocations'](None), set())
        self.assertEqual(env['pending_revocations'](
            {'_pending_revocations': ('one', 'two')}), {'one', 'two'})


if __name__ == '__main__':
    unittest.main()
