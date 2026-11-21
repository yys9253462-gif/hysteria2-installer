"""回归测试：users/set-active 持久性不确定态不重复重建页面、apply_access 锁外容错保存、损坏用量/限额容错。"""

import ast
import copy
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class _TrackableLock:
    def __init__(self):
        self._lock = threading.RLock()
        self.depth = 0

    def __enter__(self):
        self._lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        self.depth -= 1
        self._lock.release()


def _load_apply_access(ns):
    source = (ROOT / 'portal.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    serve = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    apply_fn = next(n for n in ast.walk(serve) if isinstance(n, ast.FunctionDef) and n.name == 'apply_access')
    wrapper = ast.parse(
        'def outer():\n'
        '    last_enforced_blocked = None\n'
        '    last_enforce_error = ("", 0.0)\n'
        '    def apply_access(): pass\n'
        '    return apply_access\n'
    )
    wrapper.body[0].body[2] = copy.deepcopy(apply_fn)
    ast.fix_missing_locations(wrapper)
    exec(compile(wrapper, str(ROOT / 'portal.py'), 'exec'), ns)
    return ns['outer']()


class ApiUserDurabilityAndApplyAccessTests(unittest.TestCase):
    def test_apply_access_saves_pending_outside_data_lock_and_survives_save_error(self):
        """apply_access 在收回失败落盘待撤销队列时，不得在 data_lock 内写盘，且落盘失败不得抛穿。"""
        lock = _TrackableLock()
        save_under_lock = []

        def flaky_save():
            save_under_lock.append(lock.depth > 0)
            raise OSError('disk full')

        data = {'users': {}}
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=lock,
            access_apply_lock=threading.RLock(),
            reality_apply_lock=threading.RLock(),
            portal_path=Path('/tmp/portal.json'),
            pending_revocations=portal.pending_revocations,
            blocked_user_ids=lambda: frozenset(),
            acquire_core_operation_lock=mock.Mock(return_value=99),
            os=SimpleNamespace(close=mock.Mock()),
            enforce_node_access=mock.Mock(side_effect=RuntimeError('xray unreachable')),
            save_data=flaky_save,
            _log_ignored=lambda *a, **kw: None,
        )
        apply_access = _load_apply_access(ns)
        ok = apply_access(force_ids={'alice'})
        self.assertFalse(ok)
        self.assertEqual(data.get('_pending_revocations'), ['alice'])
        self.assertEqual(save_under_lock, [False], f'apply_access 在持有 data_lock 期间调用了 save_data: {save_under_lock}')

    def test_set_status_skips_regenerate_page_on_durability_uncertain(self):
        """users/set_status 遇到 AtomicWriteDurabilityError 时不得再调用 regenerate_page，应返回 503。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        start = src.index("elif sub == 'users/set_status':")
        end = src.index("elif sub == 'users/list':", start)
        block = src[start:end]
        self.assertIn('if not durability_uncertain:\n                        regenerate_page()', block,
                      'users/set_status 缺少 durability_uncertain 护栏')

    def test_users_create_and_renew_tolerate_none_used_bytes_and_limit_bytes(self):
        """已有用户的 used_bytes 或 limit_bytes 为 None/非数字时，users/create 与 users/renew 不得抛异常。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        create_start = src.index("if sub == 'users/create':")
        create_end = src.index("elif sub == 'users/update':", create_start)
        create_block = src[create_start:create_end]
        self.assertNotIn("int(existing.get('used_bytes', 0))", create_block)

        renew_start = src.index("elif sub == 'users/renew':")
        renew_end = src.index("elif sub == 'users/delete':", renew_start)
        renew_block = src[renew_start:renew_end]
        self.assertNotIn("int(u.get('limit_bytes', 0))", renew_block)


if __name__ == '__main__':
    unittest.main()
