"""回归测试：_h_get_reality_status 停用态不白跑 qrencode；_h_post_manage_amneziawg 前置校验 peer_del/set_line 参数且 update 校验 ensure_awgctl 返回值。"""

import io
import re
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class _FakeHandler:
    def __init__(self, body: bytes = b''):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.responses = []
        self.extended = []

    def is_authenticated(self):
        return True

    def _extend_deadline(self, seconds, heavy=False):
        self.extended.append((seconds, heavy))
        return True

    def reply_json(self, code, payload):
        self.responses.append((code, payload))
        return code, payload


class RealityStatusQrAndAwgValidationTests(unittest.TestCase):
    def test_reality_status_skips_qrencode_when_inactive(self):
        """Reality 未启用（is_active=False）时，不得无谓拉起 qrencode 子进程。"""
        run_mock = mock.Mock()

        class FakePath:
            def __init__(self, p):
                self.p = str(p)

            def exists(self):
                return self.p == '/usr/local/bin/xray'

        ns = dict(
            portal.__dict__,
            Path=FakePath,
            data={'reality_config': {'uri': 'vless://u@1.2.3.4:443', 'port': 443}},
            data_lock=threading.RLock(),
            subprocess=SimpleNamespace(run=run_mock),
        )
        fn = extract_method('_h_get_reality_status', ns)
        handler = _FakeHandler()
        code, payload = fn(handler, 'reality-status')
        self.assertEqual(code, 200)
        self.assertFalse(payload['active'])
        self.assertEqual(payload['config']['qr_svg'], '')
        run_mock.assert_not_called()

    def test_manage_amneziawg_validates_peer_del_and_set_line_before_installed_and_heavy_slot(self):
        """peer_del 名称非法或 set_line 协议线非法时，未安装也应直接 400 且不申领重型槽。"""
        ns = dict(
            portal.__dict__,
            awg_installed=lambda: False,
            unit_suspended=lambda _: False,
            ensure_awgctl=mock.Mock(return_value=True),
            awg_run=mock.Mock(),
            awg_state=mock.Mock(return_value={'line': '3'}),
            awg_operation_lock=threading.RLock(),
            AWG_SVC_NAME='amneziawg-server',
            VALID_AWG_NAME_RE=re.compile(r'^[A-Za-z0-9._-]{1,32}$'),
        )
        fn = extract_method('_h_post_manage_amneziawg', ns)
        for body in (b'action=peer_del&name=../bad', b'action=set_line&line=9'):
            with self.subTest(body=body):
                h = _FakeHandler(body)
                code, payload = fn(h, '/tok/')
                self.assertEqual(code, 400, payload)
                self.assertNotIn('尚未安装', payload['error'])
                self.assertEqual(h.extended, [])

    def test_manage_amneziawg_update_fails_when_force_refresh_awgctl_fails(self):
        """action=update 时若 ensure_awgctl(force=True) 失败，必须返回 500 而不继续跑旧脚本。"""
        awg_run_mock = mock.Mock(return_value=(0, 'ok', ''))
        ensure_mock = mock.Mock(side_effect=[True, False])
        ns = dict(
            portal.__dict__,
            awg_installed=lambda: True,
            unit_suspended=lambda _: False,
            ensure_awgctl=ensure_mock,
            awg_run=awg_run_mock,
            awg_state=mock.Mock(return_value={'line': '3'}),
            awg_operation_lock=threading.RLock(),
            AWG_SVC_NAME='amneziawg-server',
            VALID_AWG_NAME_RE=re.compile(r'^[A-Za-z0-9._-]{1,32}$'),
        )
        fn = extract_method('_h_post_manage_amneziawg', ns)
        h = _FakeHandler(b'action=update')
        code, payload = fn(h, '/tok/')
        self.assertEqual(code, 500, payload)
        self.assertFalse(payload['ok'])
        self.assertIn('hy2-awgctl', payload['error'])
        awg_run_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
