"""data_lock 内绝不能写响应：慢客户端会连带卡住 /auth。

data_lock 是全局锁，/auth（每个新连接必经）与所有管理请求都要拿它。
在锁内调用 reply_json/reply 会写 socket：客户端不读、发送缓冲区满时
这次写会阻塞到连接超时（setup() 里是 5 秒，_extend_deadline 可更长），
期间所有请求都在排队 —— 表现是「面板操作偶尔整个节点掉线」。

这里用 AST 静态锁定：任何在 `with data_lock:` 内 return self.reply* 都算违规。
同时用行为测试确认冲突分支仍返回正确状态码，且**没有**改动数据。
"""
import ast
import copy
import io
from pathlib import Path
import re
import threading
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def lock_names(with_node):
    names = []
    for item in with_node.items:
        expr = item.context_expr
        if isinstance(expr, ast.Name):
            names.append(expr.id)
        elif isinstance(expr, ast.Call):
            names.extend(a.id for a in expr.args if isinstance(a, ast.Name))
    return names


def replies_inside_lock():
    hits = []

    def walk(node, stack, owner):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.With):
                walk(child, stack + lock_names(child), owner)
                continue
            if isinstance(child, ast.Return) and 'data_lock' in stack:
                text = ast.unparse(child)
                if 'reply' in text:
                    hits.append((owner, child.lineno, text[:70]))
            walk(child, stack, owner)

    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef):
            walk(node, [], node.name)
    return hits


def branch(predicate):
    return next(n for n in ast.walk(TREE) if isinstance(n, ast.If) and predicate(n))


class NoReplyInsideDataLockTests(unittest.TestCase):
    def test_no_response_is_written_while_holding_data_lock(self):
        hits = replies_inside_lock()
        self.assertEqual(hits, [], '这些位置在 data_lock 内写响应：%r' % (hits,))


class ConflictBranchTests(unittest.TestCase):
    """冲突分支：锁内只判定，锁外回包，且不写入数据。"""

    def run_api_create(self, users, params, password_taken_result):
        node = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
                    and n.name == '_h_post_do_upgrade_impl')
        # users/create 分支在 do_POST 里，直接取该 elif 分支体。
        create = next(n for n in ast.walk(TREE) if isinstance(n, ast.If)
                      and isinstance(n.test, ast.Compare)
                      and any(isinstance(c, ast.Constant) and c.value == 'users/create'
                              for c in n.test.comparators))
        state = {'users': copy.deepcopy(users)}
        env = dict(data=state, data_lock=threading.RLock(),
                   VALID_USER_ID_RE=re.compile(r'^[a-z_]+$'),
                   MASTER_USER_ID='admin_master', RESERVED_USER_IDS=frozenset({'admin_master'}),
                   password_taken=lambda u, p, o: password_taken_result,
                   rotate_user_view_key_on_change=lambda a, b: None,
                   reality_registry=lambda d: {},
                   regenerate_page=lambda: None,
                   secrets=__import__('secrets'), math=__import__('math'),
                   now_ts=1000, params=dict(params, user_id='probe'),
                   pwd='pw', expires=2000, ip_limit=0, limit_bytes=0,
                   want_active=True, note='')
        fn = ast.parse('def create(self):\n    pass').body[0]
        fn.body = copy.deepcopy(create.body)
        # 只执行到写入为止：后续同步/渲染依赖大量闭包，这里替换成 no-op 返回。
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                     '<create>', 'exec'), env)

        class Handler:
            def reply_json(self, status, payload):
                return status, payload

        try:
            result = env['create'](Handler())
        except NameError:
            # 走到需要真实闭包的分支（开户成功路径）时，说明没有提前返回。
            result = ('continued', None)
        return result, state

    def test_existing_user_conflict_returns_409_without_mutation(self):
        result, state = self.run_api_create({'probe': {'password': 'old'}},
                                            {'create_only': '1'}, False)
        self.assertEqual(result[0], 409)
        self.assertEqual(state['users']['probe'], {'password': 'old'})

    def test_password_conflict_returns_409_without_mutation(self):
        result, state = self.run_api_create({}, {'password': 'pw'}, True)
        self.assertEqual(result[0], 409)
        self.assertNotIn('probe', state['users'])


if __name__ == '__main__':
    unittest.main()
