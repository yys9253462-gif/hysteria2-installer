"""回归测试：/auth 与 /api/v1/* 请求体长度上下界防护、/auth 裸 IPv6 完整解析与全角数字拦截。"""
import ast
import copy
import io
import json
import re
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def _extract_if_branch(test_src: str, extra_env: dict):
    tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
    branch = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.If) and ast.unparse(n.test) == test_src
    )
    fn = ast.parse('def handle(self):\n    pass').body[0]
    fn.body = [copy.deepcopy(branch)]
    env = dict(
        portal.__dict__,
        data={'users': {'u1': {'password': 'pw', 'status': 'active'}}},
        data_lock=threading.RLock(),
        ip_tracker={},
        global_ip_deny={},
        live_online_ips=lambda uid: set(),
        reality_live_ips=lambda uid: set(),
        VALID_USER_ID_RE=re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
        save_data=Mock(),
        regenerate_page=Mock(),
    )
    env.update(extra_env)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                 '<auth-api-bounds>', 'exec'), env)
    return env['handle']


class _SpyRfile:
    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)
        self.read_calls = []

    def read(self, n=-1):
        self.read_calls.append(n)
        return self._buf.read(n)


class AuthAndApiBodyBoundsAndIpv6Tests(unittest.TestCase):
    def test_auth_rejects_negative_and_oversized_content_length_without_reading(self):
        """/auth 遇到负值或超大 Content-Length 时不得调用 rfile.read，直接按 Bad auth request 拒绝。"""
        fn = _extract_if_branch("self.path == '/auth'", {})
        for cl in ('-1', '65537', '100000000'):
            rfile = _SpyRfile(b'{"auth":"pw","addr":"1.2.3.4:1234"}')
            h = SimpleNamespace(
                path='/auth',
                client_address=('127.0.0.1', 1234),
                headers={'Content-Length': cl},
                rfile=rfile,
                auth_rate_limited=lambda: False,
                record_auth_failure=Mock(),
                reply_json=lambda status, payload: (status, payload),
            )
            status, payload = fn(h)
            self.assertEqual(status, 200)
            self.assertEqual(payload, {'ok': False, 'msg': 'Bad auth request'})
            self.assertEqual(rfile.read_calls, [], f'Content-Length={cl} 时不应调用 rfile.read')

    def test_auth_parses_bare_ipv6_without_truncating_last_hextet(self):
        """/auth 收到不带端口的裸 IPv6 地址（如 2001:db8::1）时不得被 rsplit(':') 截断绕过设备黑名单。"""
        fn = _extract_if_branch(
            "self.path == '/auth'",
            {'global_ip_deny': {'u1': {'2001:db8::1': 9999999999}}},
        )
        body = json.dumps({'auth': 'pw', 'addr': '2001:db8::1'}).encode('utf-8')
        h = SimpleNamespace(
            path='/auth',
            client_address=('127.0.0.1', 1234),
            headers={'Content-Length': str(len(body))},
            rfile=io.BytesIO(body),
            auth_rate_limited=lambda: False,
            record_auth_failure=Mock(),
            reply_json=lambda status, payload: (status, payload),
        )
        with patch.object(time, 'time', return_value=1000.0):
            status, payload = fn(h)
        self.assertEqual(status, 200)
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['msg'], 'Device limit exceeded across nodes')

    def test_api_v1_rejects_negative_and_oversized_content_length_without_reading(self):
        """POST /api/v1/* 遇到负值或超限 Content-Length 必须直接返回 400 且不读取 rfile。"""
        fn = _extract_if_branch("self.path.startswith('/api/v1/')", {})
        for cl in ('-1', '1048577', '999999999'):
            rfile = _SpyRfile(b'{}')
            h = SimpleNamespace(
                path='/api/v1/users/create',
                headers={'Content-Length': cl},
                rfile=rfile,
                verify_api_key=lambda: True,
                check_rate_limit=lambda bucket='api': True,
                reply=lambda status, body: (status, body),
                reply_json=lambda status, payload: (status, payload),
            )
            status, payload = fn(h)
            self.assertEqual(status, 400, f'Content-Length={cl} 应直接返回 400')
            self.assertEqual(rfile.read_calls, [], f'Content-Length={cl} 不得调用 rfile.read')

    def test_api_v1_users_rejects_fullwidth_numeric_strings(self):
        """POST /api/v1/users/create 的整数字段必须拒绝全角数字字符串。"""
        fn = _extract_if_branch("self.path.startswith('/api/v1/')", {})
        body = json.dumps({
            'user_id': 'fw_user',
            'duration_days': '\uff13\uff10',
        }).encode('utf-8')
        h = SimpleNamespace(
            path='/api/v1/users/create',
            headers={'Content-Length': str(len(body))},
            rfile=io.BytesIO(body),
            verify_api_key=lambda: True,
            check_rate_limit=lambda bucket='api': True,
            reply=lambda status, body: (status, body),
            reply_json=lambda status, payload: (status, payload),
        )
        status, payload = fn(h)
        self.assertEqual(status, 400)
        self.assertFalse(payload['ok'])


if __name__ == '__main__':
    unittest.main()
