"""API 错误回复不带文件路径等内部细节（2026-11-04 修）。

proxy-services/add 与 delete 在 API 通道（低权限 api_key）上把异常原文回给调用方：
OSError 带着 /etc/hysteria/... 的绝对路径。主动抛的 RuntimeError 是写给人看的说明，照给。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class ApiErrorTextTests(unittest.TestCase):
    def test_internal_errors_hide_paths(self):
        exc = PermissionError(13, 'Permission denied', '/etc/hysteria/gost.yml')
        text = portal.api_error_text(exc)
        self.assertNotIn('/etc/hysteria', text)
        self.assertEqual(text, 'PermissionError')

    def test_deliberate_messages_are_kept(self):
        self.assertEqual(portal.api_error_text(RuntimeError('请先安装 GOST')), '请先安装 GOST')

    def test_proxy_api_error_reply_hides_paths(self):
        """走真实的 API 分支：_manage_proxy_operation 抛 OSError 时回复里没有路径。"""
        import ast, copy, io, json, threading
        tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == "sub == 'proxy-services/add'")
        fn = ast.parse('def run(self, params):\n    pass').body[0]
        fn.body = copy.deepcopy(branch.body)
        env = {'api_error_text': portal.api_error_text}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<api>', 'exec'), env)

        class H:
            def _manage_proxy_operation(self, action, params):
                raise PermissionError(13, 'Permission denied', '/etc/hysteria/gost.yml')
            def reply_json(self, status, payload):
                return status, payload
        status, payload = env['run'](H(), {})
        self.assertEqual(status, 500)
        self.assertNotIn('/etc/hysteria', payload['error'])
        self.assertIn('PermissionError', payload['error'])

if __name__ == '__main__':
    unittest.main()
