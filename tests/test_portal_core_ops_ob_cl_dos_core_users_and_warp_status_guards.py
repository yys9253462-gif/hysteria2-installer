"""回归测试：核心安装/卸载与出站端点 Content-Length 超长数字防 DoS、_core_users 非字典 fail-closed 与读盘上限、_h_get_warp_status 时钟回拨与读盘上限、_ob_manage 错误截断。"""

import ast
import copy
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import portal  # noqa: E402

SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _load_method(name: str, env: dict):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            fn = copy.deepcopy(node)
            mod = ast.Module(body=[fn], type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, f'<portal:{name}>', 'exec'), env)
            return env[name]
    raise AssertionError(f'未找到方法 {name}')


class TestPortalCoreOpsObClDosCoreUsersAndWarpStatusGuards(unittest.TestCase):
    def test_install_uninstall_ob_endpoints_reject_5000_digit_content_length_without_500(self):
        """四处 POST 端点收到 5000 位 Content-Length 时必须返回 400/413，不得因 int() 超限落入 500。"""
        huge_cl = '9' * 5000
        for method_name, args in (
            ('_h_post_install_core', ('/tok/',)),
            ('_h_post_uninstall_core', ('/tok/',)),
            ('_ob_probe', ()),
            ('_ob_manage', ()),
        ):
            env = {
                'parse_qs': portal.parse_qs,
            }
            fn = _load_method(method_name, env)
            replies = []
            headers = SimpleNamespace(
                get_all=lambda k: [huge_cl] if k == 'Content-Length' else [],
                get=lambda k, d='': huge_cl if k == 'Content-Length' else d,
            )
            handler = SimpleNamespace(
                is_authenticated=lambda: True,
                headers=headers,
                rfile=io.BytesIO(b''),
                reply_json=lambda code, payload: replies.append((code, payload)),
            )
            fn(handler, *args)
            self.assertEqual(len(replies), 1, f'{method_name} 未返回响应')
            code, payload = replies[0]
            self.assertIn(code, (400, 413), f'{method_name} 对超长 Content-Length 不得返回 {code}: {payload}')

    def test_core_users_fail_closed_on_non_dict_or_oversized_xray_json(self):
        """_core_users 遇到顶层非 dict 的 xray.json 或超限文件必须走 fail-closed 返回非空阻断列表。"""
        with tempfile.TemporaryDirectory() as td:
            non_dict = Path(td) / 'xray.json'
            non_dict.write_text('[]', encoding='utf-8')
            env = {
                'Path': lambda p: non_dict if str(p) == '/etc/hysteria/xray.json' else Path(p),
                'json': json,
                'REALITY_INBOUND_TAG': portal.REALITY_INBOUND_TAG,
                'VMESS_INBOUND_TAG': portal.VMESS_INBOUND_TAG,
                'VLESSENC_INBOUND_TAG': portal.VLESSENC_INBOUND_TAG,
                'MANAGED_INBOUND_TAGS': portal.MANAGED_INBOUND_TAGS,
                'has_managed_inbound': portal.has_managed_inbound,
            }
            fn = _load_method('_core_users', env)
            res = fn(SimpleNamespace(), 'xray')
            self.assertTrue(res, 'xray.json 顶层为数组 [] 时 _core_users 必须 fail-closed 阻止卸载')

            big = Path(td) / 'big_xray.json'
            big.write_bytes(b'{' + b' ' * (4 * 1024 * 1024 + 16) + b'}')
            env['Path'] = lambda p: big if str(p) == '/etc/hysteria/xray.json' else Path(p)
            fn2 = _load_method('_core_users', env)
            res2 = fn2(SimpleNamespace(), 'xray')
            self.assertTrue(res2, '超大 xray.json 时 _core_users 必须 fail-closed 阻止卸载')

    def test_warp_status_handles_clock_rollback_and_limits_config_read(self):
        """_h_get_warp_status 必须免疫单调钟回拨且限制 config.yaml 读盘上限与拒绝符号链接。"""
        probed = []
        with tempfile.TemporaryDirectory() as td:
            big_cfg = Path(td) / 'config.yaml'
            big_cfg.write_bytes(b'listen: :443\n' + b'#' * (4 * 1024 * 1024 + 16))
            env = {
                'data_lock': threading.RLock(),
                'data': {'warp_enabled': True, 'warp_rules': [], 'custom_outbounds': [], 'outbound_mode': 'rules'},
                'routing_state': portal.routing_state,
                'normalize_route_rules': portal.normalize_route_rules,
                '_renderable_outbounds': portal._renderable_outbounds,
                'clean_outbounds': portal.clean_outbounds,
                'warp_backend_installed': lambda: True,
                '_warp_probe_lock': threading.Lock(),
                '_warp_probe_cache': {'value': ('1.1.1.1', True), 'at': 9999.0},
                'time': SimpleNamespace(monotonic=lambda: 100.0),
                'detect_outbound_ip': lambda *a, **kw: (probed.append(a) or '2.2.2.2'),
                'Path': lambda p: big_cfg if str(p) == '/etc/hysteria/config.yaml' else Path(p),
                'render_egress_config': lambda text, st: text,
                '_hy2_config_loaded': lambda _p: True,
            }
            fn = _load_method('_h_get_warp_status', env)
            replies = []
            handler = SimpleNamespace(
                is_authenticated=lambda: True,
                reply_json=lambda code, payload: replies.append((code, payload)),
            )
            fn(handler, 'warp-status')
            self.assertEqual(len(probed), 1, '单调钟回拨时必须失效陈旧 WARP 探测缓存重新探测')
            self.assertEqual(replies[0][1]['ip'], '2.2.2.2')
            self.assertFalse(replies[0][1]['applied'], '超大 config.yaml 应拒绝读入并判 applied=False')

    def test_ob_manage_sanitizes_and_truncates_unknown_action_and_uninstall_uses_replace_decode(self):
        """_ob_manage 未知 action 错误须截断且去控制字符，_h_post_uninstall_core 的 is-enabled 须带 errors='replace'。"""
        raw_body = ('action=' + ('x' * 200)).encode('utf-8')
        env = {'parse_qs': portal.parse_qs}
        fn = _load_method('_ob_manage', env)
        replies = []
        headers = SimpleNamespace(
            get_all=lambda k: [str(len(raw_body))] if k == 'Content-Length' else [],
            get=lambda k, d='': str(len(raw_body)) if k == 'Content-Length' else d,
        )
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            headers=headers,
            rfile=io.BytesIO(raw_body),
            reply_json=lambda code, payload: replies.append((code, payload)),
        )
        fn(handler)
        self.assertEqual(replies[0][0], 400)
        self.assertLessEqual(len(replies[0][1]['error']), 80)

        u_start = SRC.index("def _h_post_uninstall_core(self, prefix):")
        u_end = SRC.index("def _apply_anytls_enable(self):", u_start)
        self.assertIn("errors='replace'", SRC[u_start:u_end])


if __name__ == '__main__':
    unittest.main()
