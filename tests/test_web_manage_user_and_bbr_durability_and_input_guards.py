"""回归测试：Web 用户管理持久化不确定仍撤权返 503、全角配额与溢出防护，及 BBR 持久化不确定返 503 与 O_NOFOLLOW 落盘。"""

import ast
import copy
import io
import math
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
PORTAL_TREE = ast.parse(PORTAL_SRC)


def _extract_method(name, extra_ns):
    for node in ast.walk(PORTAL_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(PORTAL_SRC, node)
            dedented = '\n'.join(line[8:] if line.startswith('        ') else line for line in src.splitlines())
            ns = {
                'os': os,
                're': re,
                'sys': sys,
                'math': math,
                'time': time,
                'copy': copy,
                'secrets': secrets,
                'subprocess': subprocess,
                'Path': Path,
                'parse_qs': parse_qs,
                'VALID_USER_ID_RE': portal.USER_ID_RE,
                'MASTER_USER_ID': portal.MASTER_USER_ID,
                'RESERVED_USER_IDS': portal.RESERVED_USER_IDS,
                'QUOTA_RANGE_ERROR': b'quota range error',
                'BBR_FILE_MARKER': portal.BBR_FILE_MARKER,
                'user_id_shareable': portal.user_id_shareable,
                'password_taken': portal.password_taken,
                'pending_revocations': portal.pending_revocations,
                'user_table': portal.user_table,
                'drop_meter_totals': portal.drop_meter_totals,
                'AtomicWriteDurabilityError': portal.AtomicWriteDurabilityError,
                '_log_ignored': lambda *a, **kw: None,
            }
            ns.update(extra_ns)
            exec(dedented, ns)
            return ns[name]
    raise AssertionError(f'未找到方法 {name}')


class _FakeWebHandler:
    def __init__(self, form_dict=None, headers=None):
        raw = urlencode(form_dict or {}).encode('utf-8')
        self.rfile = io.BytesIO(raw)
        self.headers = headers if headers is not None else {'Content-Length': str(len(raw))}
        self.resp = None
        self.sync_called = 0

    def is_authenticated(self):
        return True

    def reply(self, code, body):
        self.resp = (code, body)
        return self.resp

    def reply_json(self, code, payload):
        self.resp = (code, payload)
        return self.resp

    def _sync_reality_clients(self):
        self.sync_called += 1
        return True


class WebManageUserAndBbrDurabilityAndInputGuardsTests(unittest.TestCase):
    def test_web_delete_durability_error_still_syncs_and_returns_503(self):
        """Web 表单删除用户遇 AtomicWriteDurabilityError 不得 500 跳过同步，应执行同步并返回 503。"""
        regen = Mock()
        data = {'users': {'u1': {'password': 'pw1', 'status': 'active'}}}
        fn = _extract_method('_h_post_manage_user', {
            'data': data,
            'data_lock': threading.Lock(),
            'ip_tracker': {},
            'speed_tracker': {},
            'global_ip_deny': {},
            'save_data': Mock(side_effect=portal.AtomicWriteDurabilityError('dir sync failed')),
            'regenerate_page': regen,
        })
        h = _FakeWebHandler({'action': 'delete', 'user_id': 'u1'})
        status, body = fn(h, '/tok/')
        self.assertEqual(status, 503, body)
        self.assertEqual(h.sync_called, 1, '持久化不确定时仍须立即同步协议撤权')
        regen.assert_not_called()

    def test_web_create_rejects_fullwidth_numbers_and_survives_inf_used_bytes_conflict(self):
        """Web 表单开户必须拒绝全角数字，并在重名冲突时容错旧记录 used_bytes=inf，不返回 500。"""
        data = {
            'users': {
                'dup1': {'password': 'pw1', 'status': 'active', 'used_bytes': float('inf')},
            }
        }
        fn = _extract_method('_h_post_manage_user', {
            'data': data,
            'data_lock': threading.Lock(),
            'ip_tracker': {},
            'speed_tracker': {},
            'global_ip_deny': {},
            'save_data': lambda: None,
            'regenerate_page': lambda: None,
        })
        for field, val in (('duration_days', '３０'), ('ip_limit', '２'), ('traffic_gb', '１０')):
            h = _FakeWebHandler({'action': 'create', 'user_id': 'new1', field: val})
            status, body = fn(h, '/tok/')
            self.assertEqual(status, 400, f'全角 {field}={val!r} 应返回 400，实际 {status}: {body}')

        h_dup = _FakeWebHandler({'action': 'create', 'user_id': 'dup1'})
        status_dup, body_dup = fn(h_dup, '/tok/')
        self.assertEqual(status_dup, 409, body_dup)

    def test_web_create_strips_control_chars_from_note(self):
        """Web 表单开户应对 note 剥除控制字符。"""
        data = {'users': {}}
        fn = _extract_method('_h_post_manage_user', {
            'data': data,
            'data_lock': threading.Lock(),
            'ip_tracker': {},
            'speed_tracker': {},
            'global_ip_deny': {},
            'save_data': lambda: None,
            'regenerate_page': lambda: None,
        })
        h = _FakeWebHandler({'action': 'create', 'user_id': 'clean1', 'note': 'line1\r\nline2\x00'})
        h.send_response = lambda code: setattr(h, 'resp', (code, b''))
        h.send_header = lambda k, v: None
        h.end_headers = lambda: None
        fn(h, '/tok/')
        self.assertEqual(h.resp[0], 302)
        note = data['users']['clean1']['note']
        self.assertNotIn('\n', note)
        self.assertNotIn('\r', note)
        self.assertNotIn('\x00', note)

    def test_set_bbr_rejects_fullwidth_cl_and_handles_durability_error_as_503(self):
        """_set_bbr_locked 必须拒绝全角 Content-Length，遇到 AtomicWriteDurabilityError 返回 503 且使用 O_NOFOLLOW。"""
        fn = _extract_method('_set_bbr_locked', {'data': {}, 'data_lock': threading.Lock()})
        h_fw = _FakeWebHandler({'version': 'v1'}, headers={'Content-Length': '１０'})
        status_fw, _ = fn(h_fw)
        self.assertEqual(status_fw, 400)

        # 检查 _set_bbr_locked 源码在 AtomicWriteDurabilityError 返回 503 且 _write_bbr_file 含 O_NOFOLLOW
        start = PORTAL_SRC.index('        def _set_bbr_locked(self):')
        end = PORTAL_SRC.index('        def _h_post_reboot_server(self, prefix):', start)
        block = PORTAL_SRC[start:end]
        self.assertIn('O_NOFOLLOW', block)
        self.assertIn('return self.reply_json(503,', block)


if __name__ == '__main__':
    unittest.main()
