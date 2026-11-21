"""回归测试：剩余 5 处 POST 表单拒绝负/非法 Content-Length，且 /auth 忽略 ip_tracker 中的布尔时间戳。"""

import ast
import copy
import io
import sys
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract(name, extra=None):
    tree = ast.parse(PORTAL.read_text(encoding='utf-8'))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    env = dict(portal.__dict__)
    env['parse_qs'] = parse_qs
    if extra:
        env.update(extra)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), f'<{name}>', 'exec'), env)
    return env[name]


class _BadLenHandler:
    def __init__(self, cl=-5):
        self.headers = {'Content-Length': str(cl)}
        self.rfile = io.BytesIO(b'action=state')

    def is_authenticated(self):
        return True

    def reply_json(self, status, payload):
        return status, payload

    def reply(self, status, body, mime='text/plain', www_auth=False):
        return status, body


class RemainingPostLengthAndAuthBoolTsTests(unittest.TestCase):
    def test_five_remaining_post_handlers_reject_negative_content_length_as_400(self):
        for name, args in (
            ('_h_post_manage_proxy', ('/tok/',)),
            ('_h_post_install_amneziawg', ('/tok/',)),
            ('_h_post_manage_amneziawg', ('/tok/',)),
            ('_set_bbr_locked', ()),
            ('_h_post_manage_user', ('/tok/',)),
        ):
            fn = _extract(name)
            status, _ = fn(_BadLenHandler(-5), *args)
            self.assertEqual(status, 400, f'{name} 接受了负 Content-Length 而不是返回 400')

    def test_auth_ip_tracker_filters_bool_timestamps(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index("if self.path == '/auth':")
        end = src.index("if self.path.startswith('/api/v1/'):", start)
        block = src[start:end]
        self.assertEqual(block.count('not isinstance(t, bool)'), 2,
                         '/auth 两处 ip_tracker 过滤都必须排除 bool 时间戳')


if __name__ == '__main__':
    unittest.main()
