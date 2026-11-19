"""网页管理接口残余英文参数报错与代理删除提示中文化回归测试。

验证更新目标、版本标识、五个协议管理接口、拥塞控制版本以及代理删除响应均返回中文说明。
"""
import ast
import io
import json
import re
import sys
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

SRC = Path(portal.__file__).read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def extract_handler(name, extra_ns=None):
    fn = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = dict(vars(portal))
    ns.update({'parse_qs': parse_qs, 'Path': Path, 'json': json, 're': re})
    if extra_ns:
        ns.update(extra_ns)
    mod = ast.Module(body=[fn], type_ignores=[])
    exec(compile(ast.fix_missing_locations(mod), f'<{name}>', 'exec'), ns)
    return ns[name]


class FakeHandler:
    def __init__(self, body=''):
        raw = body.encode('utf-8')
        self.headers = {'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.replies = []

    def is_authenticated(self):
        return True

    def reply_json(self, code, payload):
        self.replies.append((code, payload))
        return code, payload


class WebHandlerChineseMessagesTests(unittest.TestCase):
    def assertChineseMessage(self, text):
        self.assertTrue(re.search(r'[\u4e00-\u9fff]', text), f'期望中文提示，实际：{text!r}')
        self.assertNotIn('Invalid ', text)
        self.assertNotIn('Proxy service deleted', text)

    def test_do_upgrade_invalid_target_and_ref_return_chinese(self):
        fn = extract_handler('_h_post_do_upgrade_impl')
        h1 = FakeHandler('target=bogus')
        code, payload = fn(h1, '/tok/')
        self.assertEqual(code, 400)
        self.assertFalse(payload['ok'])
        self.assertChineseMessage(payload['error'])

        h2 = FakeHandler('target=portal&ref=not-a-sha')
        code, payload = fn(h2, '/tok/')
        self.assertEqual(code, 400)
        self.assertFalse(payload['ok'])
        self.assertChineseMessage(payload['error'])

    def test_protocol_manage_handlers_invalid_action_return_chinese(self):
        cases = [
            ('_h_post_manage_reality', {}),
            ('_h_post_manage_vmess', {}),
            ('_h_post_manage_anytls', {'_active_anytls_config': lambda: None}),
            ('_h_post_manage_tuic', {'_active_tuic_config': lambda: None}),
            ('_h_post_manage_vlessenc', {}),
        ]
        for name, extra in cases:
            with self.subTest(handler=name):
                fn = extract_handler(name, extra)
                h = FakeHandler('action=bogus')
                code, payload = fn(h, '/tok/')
                self.assertEqual(code, 400)
                self.assertFalse(payload['ok'])
                self.assertChineseMessage(payload['error'])

    def test_set_bbr_invalid_version_returns_chinese(self):
        fn = extract_handler('_set_bbr_locked')
        h = FakeHandler('version=v99')
        code, payload = fn(h)
        self.assertEqual(code, 400)
        self.assertFalse(payload['ok'])
        self.assertChineseMessage(payload['error'])

    def test_manage_proxy_delete_message_is_chinese(self):
        from unittest.mock import patch
        data = {'proxy_services': [{'id': 'proxy_1', 'type': 'socks5', 'port': 12345}]}
        extra = {
            'gost_operation_lock': threading.RLock(),
            'gost_owned': lambda: True,
            'proxy_apply_lock': threading.RLock(),
            'data_lock': threading.RLock(),
            'data': data,
            'gost_status': lambda: True,
            'save_data': lambda: None,
            'reload_gost': lambda: True,
            'protocol_port_in_use': lambda *a, **kw: False,
            'firewall_port': lambda *a, **kw: True,
        }
        fn = extract_handler('_manage_proxy_operation', extra)
        with patch.object(Path, 'exists', return_value=True):
            code, payload = fn(FakeHandler(), 'delete', {'id': 'proxy_1'})
        self.assertEqual(code, 200)
        self.assertTrue(payload['ok'])
        self.assertChineseMessage(payload['message'])


if __name__ == '__main__':
    unittest.main()
