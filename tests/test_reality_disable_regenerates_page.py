"""回归测试：Reality 停用后必须调用 regenerate_page 清理订阅残留，且非对象 xray.json 必须返回清晰 500 提示。"""

import contextlib
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402
from test_portal_web_workflows import extract_method  # noqa: E402


class _FakeHandler:
    def __init__(self, body: bytes):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.responses = []

    def is_authenticated(self):
        return True

    def reply_json(self, code, payload):
        self.responses.append((code, payload))
        return code, payload


class RealityDisableRegeneratesPageTests(unittest.TestCase):
    def _build_fn(self, xray_file: Path, regen_mock, apply_mock):
        real_path = Path

        def fake_path(p):
            if str(p) == '/etc/hysteria/xray.json':
                return xray_file
            return real_path(p)

        ns = dict(
            portal.__dict__,
            Path=fake_path,
            data={'reality_config': {'port': 8443}},
            data_lock=threading.RLock(),
            core_operation_lock=threading.RLock(),
            core_operation_file_lock=lambda: contextlib.nullcontext(),
            reality_apply_lock=threading.RLock(),
            apply_xray_config_transaction=apply_mock,
            unit_suspended=lambda _: False,
            close_protocol_port=lambda *a, **kw: True,
            regenerate_page=regen_mock,
        )
        return extract_method('_h_post_manage_reality', ns)

    def test_disable_reality_calls_regenerate_page(self):
        """停用 Reality 成功后必须调用 regenerate_page()，避免订阅里继续残留已关闭节点。"""
        with tempfile.TemporaryDirectory() as td:
            xray_file = Path(td) / 'xray.json'
            xray_file.write_text(json.dumps({
                'inbounds': [{'tag': portal.REALITY_INBOUND_TAG, 'port': 8443, 'protocol': 'vless'}]
            }), encoding='utf-8')
            regen_mock = mock.Mock()
            apply_mock = mock.Mock()
            fn = self._build_fn(xray_file, regen_mock, apply_mock)
            handler = _FakeHandler(b'action=disable')
            code, payload = fn(handler, '/tok/')
            self.assertEqual(code, 200, payload)
            self.assertTrue(payload['ok'])
            self.assertFalse(payload['active'])
            apply_mock.assert_called_once()
            regen_mock.assert_called_once()

    def test_non_dict_xray_json_returns_clear_500(self):
        """xray.json 内容为数组等非 JSON 对象时应返回清晰 500 提示且不做修改。"""
        with tempfile.TemporaryDirectory() as td:
            xray_file = Path(td) / 'xray.json'
            xray_file.write_text('["not-an-object"]', encoding='utf-8')
            regen_mock = mock.Mock()
            apply_mock = mock.Mock()
            fn = self._build_fn(xray_file, regen_mock, apply_mock)
            handler = _FakeHandler(b'action=disable')
            code, payload = fn(handler, '/tok/')
            self.assertEqual(code, 500, payload)
            self.assertFalse(payload['ok'])
            self.assertIn('xray.json', payload['error'])
            apply_mock.assert_not_called()
            regen_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
