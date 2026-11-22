"""回归测试：users/delete 持久化不确定仍执行撤权并返 503、users/create 脏旧额与空备注容错、users/renew 拒全角流量与 /api/v1 长度校验。"""

import ast
import copy
import email.message
import io
import json
import math
import re
import secrets
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _extract_api_v1_branch(extra_ns):
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'do_POST':
            for child in ast.walk(node):
                if (isinstance(child, ast.If)
                        and isinstance(child.test, ast.Call)
                        and isinstance(child.test.func, ast.Attribute)
                        and child.test.func.attr == 'startswith'
                        and child.test.args
                        and isinstance(child.test.args[0], ast.Constant)
                        and child.test.args[0].value == '/api/v1/'):
                    src = ast.get_source_segment(PORTAL_SRC, child)
                    lines = src.splitlines()
                    indent = len(lines[0]) - len(lines[0].lstrip())
                    body = ['def _run(self):']
                    for line in lines:
                        body.append('    ' + (line[indent:] if len(line) >= indent else line))
                    ns = {
                        'json': json,
                        're': re,
                        'math': math,
                        'time': time,
                        'copy': copy,
                        'secrets': secrets,
                        'Path': Path,
                        '_utf8_encodable': portal._utf8_encodable,
                        'VALID_USER_ID_RE': portal.USER_ID_RE,
                        'MASTER_USER_ID': portal.MASTER_USER_ID,
                        'RESERVED_USER_IDS': portal.RESERVED_USER_IDS,
                        'user_id_shareable': portal.user_id_shareable,
                        'password_taken': portal.password_taken,
                        'pending_revocations': portal.pending_revocations,
                        'rotate_user_view_key_on_change': portal.rotate_user_view_key_on_change,
                        'reconcile_meter_usage': portal.reconcile_meter_usage,
                        'restore_meter_user': portal.restore_meter_user,
                        'drop_meter_totals': portal.drop_meter_totals,
                        'reality_registry': portal.reality_registry,
                        'config_section': portal.config_section,
                        'artifacts': portal.artifacts,
                        'reality_uri_for_user': portal.reality_uri_for_user,
                        'reality_uuid_for_user': portal.reality_uuid_for_user,
                        'vmess_uri_for_user': portal.vmess_uri_for_user,
                        'vmess_uuid_for_user': portal.vmess_uuid_for_user,
                        'vlessenc_uri_for_user': portal.vlessenc_uri_for_user,
                        'anytls_uri_for_user': portal.anytls_uri_for_user,
                        'tuic_uri_for_user': portal.tuic_uri_for_user,
                        'AtomicWriteDurabilityError': portal.AtomicWriteDurabilityError,
                        'ANYTLS_SERVICE': portal.ANYTLS_SERVICE,
                        'TUIC_SERVICE': portal.TUIC_SERVICE,
                    }
                    ns.update(extra_ns)
                    exec('\n'.join(body), ns)
                    return ns['_run']
    raise AssertionError('未找到 POST /api/v1/ 分支')


class _FakeApiHandler:
    def __init__(self, path, payload_dict=None, headers=None):
        self.path = path
        raw = json.dumps(payload_dict or {}).encode('utf-8')
        self.rfile = io.BytesIO(raw)
        self.headers = headers if headers is not None else {'Content-Length': str(len(raw))}
        self.resp = None

    def verify_api_key(self):
        return True

    def check_rate_limit(self, bucket='api'):
        return True

    def reply(self, code, data):
        self.resp = (code, data)
        return self.resp

    def reply_json(self, code, data):
        self.resp = (code, data)
        return self.resp

    def _sync_reality_clients(self):
        return True

    def _kick_old_password_sessions(self, uid):
        return None


class ApiUsersDeleteDurabilityCreateCorruptAndRenewGuardsTests(unittest.TestCase):
    def test_users_delete_durability_error_still_applies_access_and_returns_503(self):
        """users/delete 遭遇 AtomicWriteDurabilityError 不得抛 500 跳过撤权，应调用 apply_access 并返回 503。"""
        applied = []
        regen = Mock()
        data = {'users': {'u1': {'password': 'pw1', 'status': 'active'}}}
        fn = _extract_api_v1_branch({
            'data': data,
            'data_lock': threading.Lock(),
            'ip_tracker': {},
            'speed_tracker': {},
            'global_ip_deny': {},
            'save_data': Mock(side_effect=portal.AtomicWriteDurabilityError('dir fsync failed')),
            'regenerate_page': regen,
            'apply_access': lambda ids: (applied.extend(ids) or True),
        })
        h = _FakeApiHandler('/api/v1/users/delete', {'user_id': 'u1'})
        status, body = fn(h)
        self.assertEqual(status, 503, body)
        self.assertEqual(applied, ['u1'], '持久化不确定时仍必须立即执行 apply_access 踢人撤权')
        regen.assert_not_called()

    def test_users_create_survives_corrupt_existing_used_limit_and_null_note(self):
        """users/create 更新已有用户时，若旧 used_bytes=inf 或 limit_bytes 损坏且 note=null，不得 500 或存 'None'。"""
        data = {
            'users': {
                'u1': {
                    'password': 'pw1',
                    'status': 'active',
                    'used_bytes': float('inf'),
                    'limit_bytes': 'corrupt-str',
                    'expires_at': 0,
                }
            }
        }
        fn = _extract_api_v1_branch({
            'data': data,
            'data_lock': threading.Lock(),
            'save_data': lambda: None,
            'regenerate_page': lambda: None,
            '_active_reality_config': lambda: None,
            '_active_vmess_config': lambda: None,
            '_active_vlessenc_config': lambda: None,
            '_active_anytls_config': lambda: None,
            '_active_tuic_config': lambda: None,
            '_served_singbox_config': lambda cfg, svc: None,
            'meta_path': Path('/tmp/meta.json'),
            'read_meta_file': lambda p: {'public_ip': '1.2.3.4', 'server_name': 'vpn.example.com', 'listen_port': 443},
        })
        h = _FakeApiHandler('/api/v1/users/create', {'user_id': 'u1', 'note': None})
        status, body = fn(h)
        self.assertEqual(status, 200, body)
        self.assertEqual(data['users']['u1']['used_bytes'], 0)
        self.assertEqual(data['users']['u1']['limit_bytes'], 0)
        self.assertEqual(data['users']['u1']['note'], '')

    def test_users_renew_rejects_fullwidth_add_traffic_gb(self):
        """users/renew 必须拒绝全角数字字符串 add_traffic_gb 并返回 400。"""
        data = {'users': {'u1': {'password': 'pw1', 'status': 'active', 'expires_at': None, 'limit_bytes': 1024}}}
        fn = _extract_api_v1_branch({
            'data': data,
            'data_lock': threading.Lock(),
            'save_data': lambda: None,
            'regenerate_page': lambda: None,
        })
        h = _FakeApiHandler('/api/v1/users/renew', {'user_id': 'u1', 'extend_days': 30, 'add_traffic_gb': '１０'})
        status, body = fn(h)
        self.assertEqual(status, 400, body)

    def test_api_v1_rejects_duplicate_and_fullwidth_content_length(self):
        """POST /api/v1/* 入口须拒绝重复 Content-Length 与全角数字长度。"""
        fn = _extract_api_v1_branch({'data': {}, 'data_lock': threading.Lock()})
        dup_headers = email.message.Message()
        dup_headers.add_header('Content-Length', '2')
        dup_headers.add_header('Content-Length', '4')
        h1 = _FakeApiHandler('/api/v1/users/list', {}, headers=dup_headers)
        status1, _ = fn(h1)
        self.assertEqual(status1, 400)

        h2 = _FakeApiHandler('/api/v1/users/list', {}, headers={'Content-Length': '１０'})
        status2, _ = fn(h2)
        self.assertEqual(status2, 400)


if __name__ == '__main__':
    unittest.main()
