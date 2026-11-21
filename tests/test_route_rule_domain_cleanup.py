"""回归测试：出站分流与 WARP 规则增删应共用同一域名规范化逻辑，且拒绝非法双点域名。"""
import ast
import importlib.util
import io
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_route_dom_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)
TREE = ast.parse((ROOT / 'portal.py').read_text(encoding='utf-8'))


def _extract_method(name, ns):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
            return ns[name]
    raise AssertionError('找不到方法: ' + name)


class RouteRuleDomainCleanupTests(unittest.TestCase):
    def _call_ob(self, data, params):
        replies = []
        body = urlencode(params).encode()
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            headers={'Content-Length': str(len(body))},
            rfile=io.BytesIO(body),
            reply_json=lambda code, payload: replies.append((code, payload)),
            _reply_with_egress_apply=lambda payload, kind='outbound': replies.append((200, payload)),
        )
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            save_data=lambda: None,
        )
        _extract_method('_ob_manage', ns)(handler)
        return replies[-1]

    def _call_warp(self, data, params):
        replies = []
        body = urlencode(params).encode()
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            headers={'Content-Length': str(len(body))},
            rfile=io.BytesIO(body),
            reply_json=lambda code, payload: replies.append((code, payload)),
            _reply_with_warp_apply=lambda payload: replies.append((200, payload)),
        )
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            save_data=lambda: None,
            warp_backend_installed=lambda: True,
        )
        _extract_method('_h_post_manage_warp', ns)(handler, '/tok/')
        return replies[-1]

    def test_ob_manage_rule_del_normalizes_url_and_query_same_as_add(self):
        data = {'warp_enabled': True, 'warp_rules': [], 'custom_outbounds': []}
        code, _ = self._call_ob(data, {'action': 'rule-add', 'domain': 'https://OpenAI.com:443/chat?x=1', 'outbound': 'direct'})
        self.assertEqual(code, 200)
        self.assertEqual([r['domain'] for r in data['warp_rules']], ['openai.com'])

        code, _ = self._call_ob(data, {'action': 'rule-del', 'domain': 'https://OpenAI.com/chat?x=1'})
        self.assertEqual(code, 200)
        self.assertEqual(data['warp_rules'], [], '粘贴同一 URL 删除规则时未能删掉目标域名')

        # 带 ? 查询参数而无 / 路径的 URL 也应正常剥离后添加并删除
        code, _ = self._call_ob(data, {'action': 'rule-add', 'domain': 'https://example.org?ref=1', 'outbound': 'direct'})
        self.assertEqual(code, 200)
        self.assertEqual([r['domain'] for r in data['warp_rules']], ['example.org'])

    def test_warp_del_rule_normalizes_url_same_as_add_rule(self):
        data = {'warp_enabled': True, 'warp_rules': [{'domain': 'claude.ai', 'outbound': 'warp_socks'}]}
        code, _ = self._call_warp(data, {'action': 'del_rule', 'domain': 'https://Claude.ai:443/new'})
        self.assertEqual(code, 200)
        self.assertEqual(data['warp_rules'], [], 'WARP del_rule 未按与 add_rule 相同的规则清洗域名')

    def test_add_rule_rejects_consecutive_dots_domain(self):
        data = {'warp_enabled': True, 'warp_rules': [], 'custom_outbounds': []}
        code1, _ = self._call_ob(data, {'action': 'rule-add', 'domain': 'bad..example.com', 'outbound': 'direct'})
        self.assertEqual(code1, 400)
        code2, _ = self._call_warp(data, {'action': 'add_rule', 'domain': 'bad..example.com'})
        self.assertEqual(code2, 400)


if __name__ == '__main__':
    unittest.main()
