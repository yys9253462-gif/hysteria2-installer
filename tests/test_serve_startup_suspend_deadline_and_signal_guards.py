"""回归测试：门户启动端口校验、超额停用逐单元隔离、死线续期参数防护、证书状态 SAN 容错与退出信号防重入。"""

import ast
import math
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _extract_nested_func(parent_name, target_name):
    """按名称提取嵌套在 serve() 内部的函数或类节点。"""
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == parent_name:
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.ClassDef)) and sub.name == target_name:
                    return sub
    raise AssertionError(f'未在 {parent_name} 中找到 {target_name}')


class ServeStartupSuspendDeadlineAndSignalGuardsTests(unittest.TestCase):
    def test_extend_deadline_rejects_nan_inf_bool_and_non_positive_seconds(self):
        """extend_deadline 必须忽略 nan/inf/bool/非正数/非数值，避免死线被写坏逃逸看门狗。"""
        cls_node = _extract_nested_func('serve', 'ThreadingHTTPServer')
        method_node = next(
            n for n in cls_node.body
            if isinstance(n, ast.FunctionDef) and n.name == 'extend_deadline'
        )
        src = ast.get_source_segment(PORTAL_SRC, method_node)
        ns = {'math': math, 'time': __import__('time')}
        exec('def _dummy():\n    pass\n', ns)
        # 去掉类方法缩进后编译成独立函数验证真实行为
        dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
        exec(dedented, ns)
        extend_deadline = ns['extend_deadline']

        class FakeServer:
            def __init__(self):
                import threading
                self.deadline_lock = threading.Lock()
                self.deadlines = {'req': 100.0}

        srv = FakeServer()
        for bad in (float('nan'), float('inf'), float('-inf'), 0, -10, True, False, '30', None):
            extend_deadline(srv, 'req', bad)
            self.assertEqual(srv.deadlines['req'], 100.0, f'异常秒数 {bad!r} 不得改写已有死线')

        extend_deadline(srv, 'req', 60)
        self.assertGreater(srv.deadlines['req'], 100.0)

    def test_cert_status_handler_ignores_non_string_sans_and_common_name(self):
        """_h_get_cert_status 遍历 sans 遇到非字符串元素时不得抛 AttributeError。"""
        fn_node = _extract_nested_func('serve', '_h_get_cert_status')
        src = ast.get_source_segment(PORTAL_SRC, fn_node)
        dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())

        captured = {}

        class FakeHandler:
            def is_authenticated(self):
                return True

            def reply_json(self, code, payload):
                captured['code'] = code
                captured['payload'] = payload
                return code, payload

        ns = {
            'meta_path': Path('/tmp/client_meta.json'),
            'read_meta_file': lambda p: {},
            'cert_status': lambda root, meta, selfheal_state_path='': {
                'ok': True,
                'server_name': 'other.example.com',
                'sans': [None, 123, '*.example.com', 'valid.example.com'],
                'common_name': 456,
            },
            'certificate_covers_domain': lambda domain, sans, cn: False,
            '_is_dns_name': portal._is_dns_name,
            'CERT_EXPIRY_WARN_DAYS': 14,
            'CERT_EXPIRY_CRITICAL_DAYS': 3,
        }
        exec(dedented, ns)
        ns['_h_get_cert_status'](FakeHandler(), '/api/cert-status')
        self.assertEqual(captured['code'], 200)
        self.assertEqual(captured['payload']['live_server_name'], 'valid.example.com')

    def test_serve_validates_port_with_valid_port_before_binding(self):
        """serve() 启动校验必须拦截非对象 JSON 与非法 port，并给出明确中文 SystemExit。"""
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'portal.json'
            p.write_text('[]', encoding='utf-8')
            with self.assertRaises(SystemExit) as ctx_list:
                portal.serve(str(p))
            self.assertIn('JSON 对象', str(ctx_list.exception))

            for bad_port in ('bad', 0, -1, 70000, True, None):
                p.write_text(json.dumps({
                    'port': bad_port,
                    'token': 't',
                    'auth_hash': 'h',
                    'users': {},
                }), encoding='utf-8')
                with self.assertRaises(SystemExit, msg=f'非法端口 {bad_port!r} 必须被 serve() 拒绝') as ctx:
                    portal.serve(str(p))
                self.assertIn('port 无效', str(ctx.exception))

    def test_startup_suspend_replay_isolates_unit_timeout_and_filters_bad_units(self):
        """启动重放超额停用时，单个单元超时或非法单元名不得阻断后续单元停止。"""
        start = PORTAL_SRC.index('    # 超额停用要扛住重启：')
        end = PORTAL_SRC.index('    if usage_meter is not None:', start)
        block = PORTAL_SRC[start:end]

        # 从源码块构造成可执行函数，真跑一遍单单元超时 + 非法单元名场景
        dedented_lines = [line[4:] if line.startswith('    ') else line for line in block.splitlines()]
        fn_src = 'def _replay_suspend(data, data_lock, suspend_state, subprocess, sys):\n' + '\n'.join(
            ('    ' + ln) if ln else '' for ln in dedented_lines
        )
        stopped = []

        class FakeSubprocess:
            TimeoutExpired = subprocess.TimeoutExpired

            @staticmethod
            def run(cmd, **kwargs):
                unit = cmd[-1]
                stopped.append(unit)
                if unit == 'hysteria-server.service':
                    raise subprocess.TimeoutExpired(cmd, 20)
                return mock.Mock(returncode=0)

        ns = {}
        exec(fn_src, ns)
        import io
        fake_sys = mock.Mock(stderr=io.StringIO())
        ns['_replay_suspend'](
            {},
            __import__('threading').Lock(),
            lambda d: {
                'suspended': True,
                'units': [None, 123, '--all', 'bad unit', 'hysteria-server.service', 'xray.service', 'sing-box-anytls.service'],
            },
            FakeSubprocess,
            fake_sys,
        )
        self.assertEqual(
            stopped,
            ['hysteria-server.service', 'xray.service', 'sing-box-anytls.service'],
            '首单元超时后必须继续停止其余合法单元，同时跳过非字符串与以 - 开头或含空白的脏单元名',
        )

    def test_flush_and_exit_guards_reentry_and_registers_sigint(self):
        """退出信号处理器必须防重入并同时注册 SIGTERM 与 SIGINT。"""
        start = PORTAL_SRC.index("    _exiting = {'flag': False}")
        end = PORTAL_SRC.index('    server.serve_forever()', start)
        block = PORTAL_SRC[start:end]
        self.assertIn('signal.SIGTERM', block)
        self.assertIn('signal.SIGINT', block, '主线程退出保存也应捕获 SIGINT，避免前台中断丢失计量')
        # 验证重入不会二次调用 save_data
        dedented_lines = [line[4:] if line.startswith('    ') else line for line in block.splitlines()]
        # 仅取到注册前即可测试 _flush_and_exit 本体
        sig_idx = next(i for i, ln in enumerate(dedented_lines) if 'threading.current_thread()' in ln)
        fn_src = 'def _make_handler(save_data, sys):\n' + '\n'.join(
            ('    ' + ln) if ln else '' for ln in dedented_lines[:sig_idx]
        ) + '\n    return _flush_and_exit\n'
        ns = {}
        exec(fn_src, ns)
        calls = {'n': 0}

        def reentrant_save():
            calls['n'] += 1
            if calls['n'] == 1:
                handler(15, None)

        import io
        handler = ns['_make_handler'](reentrant_save, mock.Mock(stderr=io.StringIO()))
        with self.assertRaises(SystemExit) as ctx:
            handler(15, None)
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(calls['n'], 1, '信号重入时不得重复并发执行 save_data()')


if __name__ == '__main__':
    unittest.main()
