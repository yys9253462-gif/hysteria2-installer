"""回归测试：_ob_manage 删除最后一个自定义出站时，必须同步将 outbound_mode 从 global 重置为 rules 并落盘。"""

import io
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class _FakeObHandler:
    def __init__(self, body: bytes):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.applied = []
        self.replied = []

    def is_authenticated(self):
        return True

    def reply_json(self, code, payload):
        self.replied.append((code, payload))
        return code, payload

    def _reply_with_egress_apply(self, payload, kind='outbound'):
        self.applied.append((payload, kind))
        return 200, payload


class OutboundDeleteResetsGlobalModeTests(unittest.TestCase):
    def test_deleting_last_outbound_resets_global_mode_before_save(self):
        """全局出口模式下删除最后一个自定义出站，在 save_data 前就必须把 outbound_mode 切回 rules。"""
        data = {
            'outbound_mode': 'global',
            'custom_outbounds': [{'name': 'only_socks', 'type': 'socks5', 'addr': '127.0.0.1:1080'}],
            'warp_rules': [{'domain': 'example.com', 'outbound': 'only_socks'}],
        }
        saved_mode = []

        def fake_save():
            saved_mode.append(data.get('outbound_mode'))

        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            save_data=fake_save,
        )
        fn = extract_method('_ob_manage', ns)
        h = _FakeObHandler(b'action=delete&name=only_socks')
        code, _ = fn(h)
        self.assertEqual(code, 200)
        self.assertEqual(data['custom_outbounds'], [])
        self.assertEqual(data['outbound_mode'], 'rules', '删光自定义出站后 outbound_mode 仍残留在 global')
        self.assertEqual(saved_mode, ['rules'], '切回 rules 的状态未随本次 save_data 落盘')


if __name__ == '__main__':
    unittest.main()
