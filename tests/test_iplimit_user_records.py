"""损坏账户不能让设备上限 worker 撤销其他账户的拦截。"""
import ast
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


class IplimitUserRecordTests(unittest.TestCase):
    def limits(self, users):
        tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
        worker = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                      and n.name == 'reality_iplimit_worker')
        assignment = next(n for n in ast.walk(worker) if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'limits' for t in n.targets))
        env = dict(portal.__dict__, data={'users': users})
        exec(compile(ast.Module(body=[copy.deepcopy(assignment)], type_ignores=[]),
                     '<worker-limits>', 'exec'), env)
        return env['limits']

    def test_bad_record_does_not_cancel_valid_user_limits(self):
        for bad in (None, [], 'broken', {'ip_limit': 'invalid'},
                    {'ip_limit': None}, {'ip_limit': float('inf')}):
            with self.subTest(bad=bad):
                self.assertEqual(self.limits({'good': {'ip_limit': 2}, 'bad': bad}), {'good': 2})

    def test_only_active_admitted_positive_limits_are_returned(self):
        self.assertEqual(self.limits({'good': {'ip_limit': '3'},
            'disabled': {'ip_limit': 2, 'status': 'disabled'},
            'expired': {'ip_limit': 2, 'expires_at': 0},
            'quota': {'ip_limit': 2, 'limit_bytes': 1, 'used_bytes': 1},
            'unlimited': {'ip_limit': 0}, 'negative': {'ip_limit': -1}}), {'good': 3})


if __name__ == '__main__':
    unittest.main()
