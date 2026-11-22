"""回归测试：重复/非 ASCII Content-Length 拒绝、/auth 畸形方括号 IPv6 后缀拒绝、auth_rate_key 控制字符防日志注入与 capabilities 脏字段清洗。"""

import ast
import email.message
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _extract_handler_method(name, extra_ns):
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(PORTAL_SRC, node)
            dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
            ns = {
                'json': json,
                're': __import__('re'),
                'ipaddress': __import__('ipaddress'),
                'time': __import__('time'),
                'math': __import__('math'),
                'hmac': __import__('hmac'),
                'Path': Path,
                'PORTAL_VERSION': portal.PORTAL_VERSION,
                'clean_node_identity': portal.clean_node_identity,
                '_clean_host_scalar': portal._clean_host_scalar,
                '_valid_port': portal._valid_port,
                'clean_hop_range': portal.clean_hop_range,
                'config_section': portal.config_section,
                'user_table': portal.user_table,
                'proxy_services': portal.proxy_services,
                'managed_inbound_active': portal.managed_inbound_active,
                '_reality_public_params': portal._reality_public_params,
                'VMESS_INBOUND_TAG': portal.VMESS_INBOUND_TAG,
                'REALITY_INBOUND_TAG': portal.REALITY_INBOUND_TAG,
                'VLESSENC_INBOUND_TAG': portal.VLESSENC_INBOUND_TAG,
                'ANYTLS_SERVICE': portal.ANYTLS_SERVICE,
                'TUIC_SERVICE': portal.TUIC_SERVICE,
                'AWG_SVC_NAME': 'amneziawg-server',
                'auth_rate_key': portal.auth_rate_key,
            }
            ns.update(extra_ns)
            exec(dedented, ns)
            return ns[name]
    raise AssertionError(f'未找到方法 {name}')


class HttpPostClAuthBracketAndCapabilitiesGuardsTests(unittest.TestCase):
    def test_auth_rate_key_strips_control_chars_to_prevent_log_injection(self):
        """auth_rate_key 对无法解析为 IP 的来源字符串必须剔除换行/控制字符，防止日志伪造注入。"""
        got = portal.auth_rate_key('1.2.3.4\r\n[portal] FAKE LOG\x00')
        self.assertNotIn('\n', got)
        self.assertNotIn('\r', got)
        self.assertNotIn('\x00', got)

    def test_do_post_rejects_duplicate_or_fullwidth_or_signed_content_length(self):
        """do_POST 必须拒绝重复 Content-Length 头、全角数字及带符号长度，返回 400。"""
        fn = _extract_handler_method('do_POST', {})

        class FakeHandler:
            def __init__(self, headers):
                self.headers = headers
                self.path = '/auth'
                self.client_address = ('127.0.0.1', 12345)
                self.resp = None

            def reply_json(self, code, payload):
                self.resp = (code, payload)
                return self.resp

        # 重复 Content-Length
        msg_dup = email.message.Message()
        msg_dup.add_header('Content-Length', '10')
        msg_dup.add_header('Content-Length', '20')
        h1 = FakeHandler(msg_dup)
        fn(h1)
        self.assertEqual(h1.resp[0], 400)

        for bad_cl in ('１０', '+10', '-5'):
            h = FakeHandler({'Content-Length': bad_cl})
            fn(h)
            self.assertEqual(h.resp[0], 400, f'异常 Content-Length={bad_cl!r} 必须返回 400')

    def test_auth_rejects_bracketed_ipv6_with_invalid_trailing_suffix(self):
        """/auth 面对 [2001:db8::1]garbage 畸形后缀不得静默接受并提取 IP。"""
        fn = _extract_handler_method('do_POST', {
            'data_lock': __import__('threading').Lock(),
            'data': {'users': {'u1': {'password': 'pw', 'status': 'active'}}},
            'global_ip_deny': {},
            'ip_tracker': {},
            'IP_TIMEOUT_SECONDS': 180,
            'user_access_denial': portal.user_access_denial,
            'active_ip_deny': portal.active_ip_deny,
            'user_ip_limit': portal.user_ip_limit,
            'live_online_ips': lambda uid: set(),
            'reality_live_ips': lambda uid: set(),
        })
        payload = json.dumps({'auth': 'pw', 'addr': '[2001:db8::1]garbage'}).encode('utf-8')

        class FakeAuthHandler:
            def __init__(self):
                self.headers = {'Content-Length': str(len(payload))}
                self.path = '/auth'
                self.client_address = ('127.0.0.1', 12345)
                self.rfile = io.BytesIO(payload)
                self.resp = None
                self.auth_fails = 0

            def auth_rate_limited(self):
                return False

            def record_auth_failure(self):
                self.auth_fails += 1

            def reply_json(self, code, data):
                self.resp = (code, data)
                return self.resp

        h = FakeAuthHandler()
        fn(h)
        self.assertEqual(h.resp, (200, {'ok': False, 'msg': 'Bad auth request'}))
        self.assertEqual(h.auth_fails, 1)

    def test_capabilities_extends_deadline_and_sanitizes_corrupt_node_and_protocol_fields(self):
        """/api/v1/capabilities 必须续期连接死线，并清洗损坏的 public_ip/server_name/hop_port_range/domain。"""
        events = []
        fn = _extract_handler_method('do_GET', {
            'data_lock': __import__('threading').Lock(),
            'data': {
                'vmess_config': {'domain': 123, 'ws_path': ['bad'], 'sni': 'ok\nbad', 'port': 8444},
                'vlessenc_config': {'domain': 've.example.com\nevil', 'port': 8445},
                'anytls_config': {'domain': ['bad'], 'port': 8446},
                'tuic_config': {'domain': 'tuic.example.com', 'sni': 999, 'port': 8447},
                'users': {},
            },
            'meta_path': Path('/tmp/client_meta.json'),
            'read_meta_file': lambda p: {
                'public_ip': 12345,
                'server_name': 'bad\nname',
                'hop_port_range': 'garbage-range',
                'listen_port': 443,
            },
            '_singbox_version': lambda: None,
            '_active_anytls_config': lambda: None,
            '_active_tuic_config': lambda: None,
            '_cert_summary': lambda r, m: {},
            'subprocess': SimpleNamespace(run=lambda *a, **kw: SimpleNamespace(stdout='inactive\n')),
        })

        class FakeCapHandler:
            def __init__(self):
                self.path = '/api/v1/capabilities'
                self.resp = None

            def verify_api_key(self):
                return True

            def check_rate_limit(self, bucket='api'):
                return True

            def _extend_deadline(self, seconds, heavy=False):
                events.append(seconds)
                return True

            def reply_json(self, code, payload):
                self.resp = (code, payload)
                return self.resp

        h = FakeCapHandler()
        fn(h)
        self.assertTrue(events and max(events) >= 45, 'capabilities 多次调外部命令前须调用 _extend_deadline(>=45)')
        code, body = h.resp
        self.assertEqual(code, 200)
        self.assertIsInstance(body['node']['public_ip'], str)
        self.assertIsInstance(body['node']['server_name'], str)
        self.assertNotIn('\n', body['node']['server_name'])
        self.assertEqual(body['node']['hop_port_range'], '')
        self.assertNotIn('domain', body['protocols']['vmess'])
        self.assertNotIn('ws_path', body['protocols']['vmess'])
        self.assertNotIn('sni', body['protocols']['vmess'])
        self.assertNotIn('domain', body['protocols']['vlessenc'])
        self.assertNotIn('domain', body['protocols']['anytls'])
        self.assertEqual(body['protocols']['tuic'].get('domain'), 'tuic.example.com')
        self.assertNotIn('sni', body['protocols']['tuic'])


if __name__ == '__main__':
    unittest.main()
