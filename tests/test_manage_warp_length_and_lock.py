"""回归测试：_h_post_manage_warp 拒绝负/非法 Content-Length，且未装 WARP 时绝不先污染 data['warp_rules']。"""

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


def _extract_manage_warp(state, installed=True):
    tree = ast.parse(PORTAL.read_text(encoding='utf-8'))
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == '_h_post_manage_warp'
    )
    saved = []
    env = dict(portal.__dict__)
    env.update({
        'data': state,
        'data_lock': threading.RLock(),
        'warp_backend_installed': lambda: installed,
        'save_data': lambda: saved.append(copy.deepcopy(state)),
        'parse_qs': parse_qs,
    })
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)], type_ignores=[])), '<mw>', 'exec'), env)
    return env['_h_post_manage_warp'], saved


class _FakeHandler:
    def __init__(self, body=b'', content_length=None):
        self.headers = {'Content-Length': str(len(body) if content_length is None else content_length)}
        self.rfile = io.BytesIO(body)

    def is_authenticated(self):
        return True

    def reply_json(self, status, payload):
        return status, payload

    def _reply_with_warp_apply(self, payload):
        return 200, dict(ok=True, **payload)


class ManageWarpLengthAndLockTests(unittest.TestCase):
    def test_negative_content_length_does_not_toggle_warp(self):
        state = {'warp_enabled': True, 'warp_rules': ['openai.com']}
        fn, saved = _extract_manage_warp(state, installed=True)
        status, payload = fn(_FakeHandler(b'', content_length=-1), '/tok/')
        self.assertEqual(status, 400)
        self.assertFalse(payload['ok'])
        self.assertTrue(state['warp_enabled'], '负 Content-Length 不得被当成 toggle 翻转 WARP 开关')
        self.assertEqual(saved, [])

    def test_warp_not_installed_never_mutates_warp_rules_in_first_lock(self):
        src = PORTAL.read_text(encoding='utf-8')
        start = src.index('def _h_post_manage_warp(self, prefix):')
        end = src.index('def _h_post_install_xray(self, prefix):', start)
        block = src[start:end]
        self.assertIn('not warp_not_installed', block, '未装 WARP 时不得先写 data["warp_rules"] 再二次持锁回滚')
        # 并且外层 if warp_not_installed 不应再做二次持锁回滚
        post_lock = block[block.index('if warp_not_installed:'):block.index('save_data()')]
        self.assertNotIn('with data_lock:', post_lock)


if __name__ == '__main__':
    unittest.main()
