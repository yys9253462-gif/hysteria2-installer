import ast
import importlib.util
import io
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTAL_PATH = ROOT / 'portal.py'


def _load_portal_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('portal_batch57_item2', PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_serve_def(func_name):
    tree = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))
    serve_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    for node in serve_fn.body:
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return ast.unparse(node)
    raise AssertionError(f'未找到 serve 内函数: {func_name}')


def _extract_handler_method(method_name):
    tree = ast.parse(PORTAL_PATH.read_text(encoding='utf-8'))
    serve_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    for node in ast.walk(serve_fn):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return ast.unparse(item)
    raise AssertionError(f'未找到处理器方法: {method_name}')


class ArchiveMembersBackupSessionDosAndLogSanitizeGuardTests(unittest.TestCase):
    def test_safe_tar_and_zip_members_reject_nested_dotslash_root_and_ctrl(self):
        mod = _load_portal_module()
        for fn in (mod.safe_tar_members, mod.safe_zip_members):
            for bad in (['././/etc/passwd', 'xray'], ['././../evil', 'xray'], ['C:evil', 'xray'], ['dir/x\n', 'xray']):
                with self.subTest(fn=fn.__name__, bad=bad):
                    with self.assertRaises(ValueError):
                        fn(bad, 'xray')
            # 多层合法 ././ 前缀应正常匹配
            self.assertEqual(fn(['././xray'], 'xray'), '././xray')

    def test_prune_core_backups_skips_symlinks_and_guards_keep(self):
        mod = _load_portal_module()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            f1 = d / 'hysteria-1'
            f2 = d / 'hysteria-2'
            f1.write_bytes(b'1')
            f2.write_bytes(b'2')
            # keep=0 不应把全部备份清空，至少保留 1 份
            mod._prune_core_backups(d, keep=0)
            remaining = [p.name for p in d.iterdir()]
            self.assertEqual(len(remaining), 1)
        src = PORTAL_PATH.read_text(encoding='utf-8')
        prune_blk = src[src.index('def _prune_core_backups('):src.index('def _require_disk_space(')]
        self.assertIn('is_symlink()', prune_blk)

    def test_hysteria_asset_arch_supports_armhf_and_non_str(self):
        mod = _load_portal_module()
        self.assertEqual(mod.hysteria_asset_arch('armhf'), 'arm')
        self.assertIsNone(mod.hysteria_asset_arch(12345))

    def test_verify_session_survives_5000_digit_timestamp_and_rejects_bad_token(self):
        src = _extract_serve_def('verify_session')
        ns = {
            'data_lock': threading.Lock(),
            'data': {'token': 'goodtok', 'session_epoch': 0},
            'session_epoch': lambda: 0,
            'SESSION_MAX_AGE': 86400,
            'time': __import__('time'),
            'hmac': __import__('hmac'),
            '_session_sig': lambda t, i, e: 'sig',
        }
        exec(compile(src, str(PORTAL_PATH), 'exec'), ns)
        verify = ns['verify_session']

        # Python 3.11+ 对 >4300 位数字调 int() 会抛 ValueError；verify_session 必须安全返回 False 而不是 500
        huge_ts = '9' * 5000
        self.assertFalse(verify(f'hy2_session=goodtok.{huge_ts}.sig'))

        # 损坏的含斜杠/空白 expected_token 必须拒绝
        ns['data']['token'] = 'bad/tok'
        now_s = str(int(__import__('time').time()))
        self.assertFalse(verify(f'hy2_session=bad/tok.{now_s}.sig'))

    def test_handle_one_request_redacts_query_string_and_ctrl_chars_and_do_post_guards_huge_cl(self):
        h_src = _extract_handler_method('handle_one_request')
        err_buf = io.StringIO()
        replies = []

        class Base:
            def handle_one_request(self):
                raise RuntimeError('boom\r\nfake-log')

        ns = {'sys': type('S', (), {'stderr': err_buf})(), 're': __import__('re')}
        exec('class Dummy(Base):\n' + '\n'.join('    ' + l for l in h_src.splitlines()), {'Base': Base, **ns}, ns)
        inst = ns['Dummy']()
        inst.command = 'GET'
        inst.path = '/tok/u/alice?k=SUPER_SECRET_KEY\r\nINJECTED'
        inst._responded = False
        inst.reply_json = lambda code, body: replies.append((code, body))
        inst.handle_one_request()

        logged = err_buf.getvalue()
        self.assertNotIn('SUPER_SECRET_KEY', logged, f'异常日志不应泄露查询串密钥: {logged!r}')
        self.assertNotIn('\r', logged)
        self.assertEqual(logged.count('\n'), 1, f'异常日志不应被换行注入拆成多行: {logged!r}')

        post_src = _extract_handler_method('do_POST')
        self.assertIn('len(_raw_cl_s) > 10', post_src)


if __name__ == '__main__':
    unittest.main()
