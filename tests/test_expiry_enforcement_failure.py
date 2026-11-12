"""收回确认不了时不反复写盘、不刷屏（2026-11-12 修）。

旧实现：apply_access 每次失败都把待撤销队列整份写回 portal.json 并 fsync —— 只有到期用户、
队列为空时也写一个空列表；worker 每 5 秒重试一次，等于每 5 秒落盘一次。日志同样每 5 秒
一条，而且只有异常类名（RuntimeError），看不出是统计接口不通还是配置坏了。
从 serve() 里摘出真实的 apply_access（连同它 nonlocal 的闭包变量初值）执行。
"""
import ast
import contextlib
import copy
import io
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

FAILED = '[expiry] access enforcement failed: '


def build_apply_access(ns):
    tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
    serve = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    apply_fn = next(n for n in ast.walk(serve) if isinstance(n, ast.FunctionDef) and n.name == 'apply_access')
    names = {name for n in apply_fn.body if isinstance(n, ast.Nonlocal) for name in n.names}
    inits = [n for n in serve.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id in names for t in n.targets)]
    assert {t.id for n in inits for t in n.targets} >= names, names
    wrapper = ast.parse('def outer():\n    pass\n')
    wrapper.body[0].body = copy.deepcopy(inits) + [
        copy.deepcopy(apply_fn), ast.Return(value=ast.Name(id='apply_access', ctx=ast.Load()))]
    exec(compile(ast.fix_missing_locations(wrapper), '<apply-access>', 'exec'), ns)
    return ns['outer']()


class EnforcementFailureTests(unittest.TestCase):
    def setUp(self):
        self.clock = [1000.0]
        self.save = Mock()

    def make(self, state, enforce):
        ns = dict(vars(portal))
        ns.update(data=state, data_lock=threading.RLock(), access_apply_lock=threading.RLock(),
                  reality_apply_lock=threading.RLock(),
                  blocked_user_ids=lambda: frozenset(uid for uid, u in state['users'].items()
                                                     if not portal.user_access_allowed(u)),
                  acquire_core_operation_lock=Mock(return_value=41), os=SimpleNamespace(close=Mock()),
                  enforce_node_access=enforce, save_data=self.save,
                  portal_path=Path('/nonexistent/portal.json'),
                  time=SimpleNamespace(monotonic=lambda: self.clock[0]))
        return build_apply_access(ns)

    def run_quietly(self, fn, *calls):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            results = [fn(**kwargs) for kwargs in calls]
        return results, err.getvalue().splitlines()

    def test_repeated_failure_neither_rewrites_state_nor_floods_the_log(self):
        state = {'users': {'expired': {'status': 'active', 'expires_at': 1}}}
        enforce = Mock(side_effect=RuntimeError('cannot confirm Hy2 revocation: loopback stats unavailable'))
        results, lines = self.run_quietly(self.make(state, enforce), {}, {}, {})
        self.assertEqual(results, [False, False, False])
        self.assertEqual(self.save.call_count, 0, 'nothing new to persist, yet portal.json was rewritten')
        self.assertNotIn('_pending_revocations', state)
        self.assertEqual(lines, [FAILED + 'RuntimeError: cannot confirm Hy2 revocation: loopback stats unavailable'])

    def test_new_revocations_are_still_persisted_once(self):
        state = {'users': {}}
        enforce = Mock(side_effect=OSError('connection refused'))
        results, _ = self.run_quietly(self.make(state, enforce),
                                      {'force_ids': ('gone',)}, {'force_ids': ('gone',)}, {})
        self.assertEqual(results, [False, False, False])
        self.assertEqual(state['_pending_revocations'], ['gone'])
        self.assertEqual(self.save.call_count, 1)

    def test_a_new_reason_a_recovery_and_an_hourly_reminder_are_logged(self):
        state = {'users': {'expired': {'status': 'active', 'expires_at': 1}}}
        enforce = Mock(side_effect=[RuntimeError('a'), RuntimeError('a'), ValueError('b\nsecond line'), True,
                                    RuntimeError('a'), RuntimeError('a'), RuntimeError('a')])
        apply_access = self.make(state, enforce)
        _, lines = self.run_quietly(apply_access, {}, {}, {}, {}, {})
        self.clock[0] += 1800
        _, half_hour = self.run_quietly(apply_access, {})
        self.clock[0] += 1801
        _, hour = self.run_quietly(apply_access, {})
        self.assertEqual(lines, [FAILED + 'RuntimeError: a', FAILED + 'ValueError: b second line',
                                 '[expiry] access enforcement recovered', FAILED + 'RuntimeError: a'])
        self.assertEqual(half_hour, [])
        self.assertEqual(hour, [FAILED + 'RuntimeError: a'])


if __name__ == '__main__':
    unittest.main()
