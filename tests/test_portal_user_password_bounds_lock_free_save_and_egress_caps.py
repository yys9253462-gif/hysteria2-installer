"""回归测试：用户密码长度上限、users/create 非字符串与布尔数值校验、users/update 锁外写盘及分流规则/出站数量上限。"""

import ast
import copy
import io
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import portal  # noqa: E402

SOURCE = (REPO / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def _extract_method(name):
    node = next(
        n for n in ast.walk(TREE)
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    return node


class PortalUserPasswordBoundsLockFreeSaveAndEgressCapsTests(unittest.TestCase):
    def test_manage_user_rejects_overlong_password(self):
        """网页表单 _h_post_manage_user 超过 256 字符密码必须返回 400 且不写入 data['users']。"""
        node = _extract_method('_h_post_manage_user')
        state = {'users': {}}
        env = dict(portal.__dict__)
        env.update({
            'data': state,
            'data_lock': threading.RLock(),
            'VALID_USER_ID_RE': portal.re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
            'RESERVED_USER_IDS': {'admin_master', 'placeholder'},
            'user_id_shareable': lambda uid: bool(uid and set(uid) != {'.'}),
            'save_data': lambda: (_ for _ in ()).throw(AssertionError('超长密码不应触发写盘')),
            'regenerate_page': lambda: None,
        })
        exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), '<mu>', 'exec'), env)
        fn = env['_h_post_manage_user']

        payload = urlencode({
            'action': 'create',
            'user_id': 'alice_longpw',
            'password': 'p' * 257,
            'duration_days': '30',
            'ip_limit': '0',
            'traffic_gb': '0',
        }).encode('utf-8')

        class _H:
            headers = {'Content-Length': str(len(payload))}
            rfile = io.BytesIO(payload)
            def is_authenticated(self): return True
            def reply(self, st, body, *a, **k): return st, body.decode('utf-8', errors='replace') if isinstance(body, bytes) else body

        st, body = fn(_H(), '/tok/')
        self.assertEqual(st, 400, body)
        self.assertNotIn('alice_longpw', state['users'])

    def test_users_create_rejects_non_string_userid_bool_numbers_and_overlong_password(self):
        """REST users/create 须拦截非字符串 user_id、布尔数值（True/False）与超 256 字符密码。"""
        start = SOURCE.index("if sub == 'users/create':")
        end = SOURCE.index("if sub == 'users/update':", start)
        create_block = SOURCE[start:end]
        self.assertIn("not isinstance(params.get('user_id'), str)", create_block)
        self.assertIn("previous_reality_users", create_block)
        self.assertIn("data.pop('reality_users', None)", create_block)
        self.assertIn("len(pwd) > 256", create_block)
        self.assertIn("isinstance(_v, bool)", create_block)

        upd_start = SOURCE.index("if sub == 'users/update':")
        upd_end = SOURCE.index("if sub == 'users/delete':", upd_start)
        update_block = SOURCE[upd_start:upd_end]
        self.assertIn("len(params['password']) > 256", update_block)

    def test_users_update_and_renew_call_save_data_outside_data_lock(self):
        """REST users/update 与 users/renew 均不可在 with data_lock 锁内调用 save_data()，防止慢盘 fsync 阻塞全节点 /auth。"""
        for label, start_marker, end_marker in (
            ('users/update', "if sub == 'users/update':", "elif sub == 'users/renew':"),
            ('users/renew', "elif sub == 'users/renew':", "elif sub == 'users/delete':"),
        ):
            s_idx = SOURCE.index(start_marker)
            e_idx = SOURCE.index(end_marker, s_idx)
            lines = SOURCE[s_idx:e_idx].splitlines()
            lock_line_idx = next(i for i, l in enumerate(lines) if l.strip() == 'with data_lock:')
            base_indent = len(lines[lock_line_idx]) - len(lines[lock_line_idx].lstrip())
            in_lock_lines = []
            for line in lines[lock_line_idx + 1:]:
                if line.strip() and (len(line) - len(line.lstrip())) <= base_indent:
                    break
                in_lock_lines.append(line)
            self.assertFalse(
                any('save_data()' in l for l in in_lock_lines),
                f'{label} 仍在 data_lock 锁内调用 save_data()，会阻塞并发 /auth 鉴权',
            )

    def test_manage_warp_and_outbounds_enforce_rule_and_outbound_caps(self):
        """_h_post_manage_warp 与 _ob_manage 须分别限制分流规则（<=500）与自定义出站（<=64）上限。"""
        # 1) _h_post_manage_warp 满 500 条时拒绝新增第 501 条
        node_w = _extract_method('_h_post_manage_warp')
        existing_rules = [{'domain': f'd{i}.example.com', 'outbound': 'warp_socks'} for i in range(500)]
        state_w = {'warp_enabled': True, 'warp_rules': existing_rules}
        env_w = dict(portal.__dict__)
        env_w.update({
            'data': state_w,
            'data_lock': threading.RLock(),
            'save_data': lambda: (_ for _ in ()).throw(AssertionError('规则达上限不应写盘')),
        })
        exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node_w)], type_ignores=[])), '<mw>', 'exec'), env_w)
        fn_w = env_w['_h_post_manage_warp']

        body_w = urlencode({'action': 'add_rule', 'domain': 'extra501.example.com'}).encode('utf-8')

        class _HW:
            headers = {'Content-Length': str(len(body_w))}
            rfile = io.BytesIO(body_w)
            def is_authenticated(self): return True
            def reply_json(self, st, body): return st, body
            def _reply_with_warp_apply(self, payload): return 200, payload

        st_w, res_w = fn_w(_HW(), '/tok/')
        self.assertEqual(st_w, 400, res_w)
        self.assertEqual(len(state_w['warp_rules']), 500)

        # 2) _ob_manage 满 500 条分流规则拒绝新增第 501 条，且满 64 条自定义出站拒绝新增第 65 条
        node_o = _extract_method('_ob_manage')
        existing_outs = [
            {'name': f'ob{i}', 'type': 'socks5', 'addr': f'127.0.0.1:{20000 + i}'}
            for i in range(64)
        ]
        state_o = {'warp_enabled': True, 'warp_rules': copy.deepcopy(existing_rules), 'custom_outbounds': existing_outs}
        env_o = dict(portal.__dict__)
        env_o.update({
            'data': state_o,
            'data_lock': threading.RLock(),
            'save_data': lambda: (_ for _ in ()).throw(AssertionError('达上限不应写盘')),
        })
        exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node_o)], type_ignores=[])), '<ob>', 'exec'), env_o)
        fn_o = env_o['_ob_manage']

        body_r = urlencode({'action': 'rule-add', 'domain': 'extra501.example.com', 'outbound': 'warp_socks'}).encode('utf-8')
        body_s = urlencode({'action': 'save', 'name': 'ob65', 'type': 'socks5', 'addr': '127.0.0.1:29999'}).encode('utf-8')

        def _make_ho(raw):
            class _HO:
                headers = {'Content-Length': str(len(raw))}
                rfile = io.BytesIO(raw)
                def is_authenticated(self): return True
                def reply_json(self, st, body): return st, body
                def _reply_with_egress_apply(self, payload, **k): return 200, payload
            return _HO()

        st_r, res_r = fn_o(_make_ho(body_r))
        self.assertEqual(st_r, 400, res_r)
        st_s, res_s = fn_o(_make_ho(body_s))
        self.assertEqual(st_s, 400, res_s)


if __name__ == '__main__':
    unittest.main()
