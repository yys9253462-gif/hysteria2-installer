"""回归测试：VMess/VLESS-Enc 停用校验非对象 xray.json 与 old_state=None 清理；AnyTLS/TUIC 回滚隔离配置恢复异常不跳过服务恢复。"""

import contextlib
import io
import json
import sys
import tempfile
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
    def __init__(self, body: bytes):
        self.headers = {'Content-Length': str(len(body))}
        self.rfile = io.BytesIO(body)
        self.responses = []

    def is_authenticated(self):
        return True

    def reply_json(self, code, payload):
        self.responses.append((code, payload))
        return code, payload


class ProtocolDisableRollbackHardeningTests(unittest.TestCase):
    def test_vmess_and_vlessenc_reject_non_dict_xray_json(self):
        """VMess 与 VLESS-Enc 遇到非对象 xray.json 时必须返回明确中文 500 提示且不触发修改。"""
        for method_name in ('_h_post_manage_vmess', '_h_post_manage_vlessenc'):
            with self.subTest(method=method_name), tempfile.TemporaryDirectory() as td:
                xray_file = Path(td) / 'xray.json'
                xray_file.write_text('["bad-root"]', encoding='utf-8')
                real_path = Path

                def fake_path(p, target=xray_file):
                    return target if str(p) == '/etc/hysteria/xray.json' else real_path(p)

                apply_mock = mock.Mock()
                ns = dict(
                    portal.__dict__,
                    Path=fake_path,
                    data={},
                    data_lock=threading.RLock(),
                    core_operation_lock=threading.RLock(),
                    core_operation_file_lock=lambda: contextlib.nullcontext(),
                    reality_apply_lock=threading.RLock(),
                    apply_xray_config_transaction=apply_mock,
                    unit_suspended=lambda _: False,
                    save_data=mock.Mock(),
                    regenerate_page=mock.Mock(),
                    close_protocol_port=mock.Mock(return_value=True),
                )
                fn = extract_method(method_name, ns)
                code, payload = fn(_FakeHandler(b'action=disable'), '/tok/')
                self.assertEqual(code, 500, payload)
                self.assertFalse(payload['ok'])
                self.assertIn('xray.json', payload['error'])
                apply_mock.assert_not_called()

    def test_vmess_and_vlessenc_disable_save_failure_pops_absent_old_state(self):
        """原有 data 中无 vmess_config/vlessenc_config 时，停用 save_data 失败回滚不得残留脏键。"""
        cases = [
            ('_h_post_manage_vmess', 'vmess_config', portal.VMESS_INBOUND_TAG),
            ('_h_post_manage_vlessenc', 'vlessenc_config', portal.VLESSENC_INBOUND_TAG),
        ]
        for method_name, cfg_key, tag in cases:
            with self.subTest(method=method_name), tempfile.TemporaryDirectory() as td:
                xray_file = Path(td) / 'xray.json'
                xray_file.write_text(json.dumps({
                    'inbounds': [{'tag': tag, 'port': 2087, 'protocol': 'vmess'}]
                }), encoding='utf-8')
                real_path = Path

                def fake_path(p, target=xray_file):
                    return target if str(p) == '/etc/hysteria/xray.json' else real_path(p)

                data = {}
                ns = dict(
                    portal.__dict__,
                    Path=fake_path,
                    data=data,
                    data_lock=threading.RLock(),
                    core_operation_lock=threading.RLock(),
                    core_operation_file_lock=lambda: contextlib.nullcontext(),
                    reality_apply_lock=threading.RLock(),
                    apply_xray_config_transaction=mock.Mock(),
                    unit_suspended=lambda _: False,
                    save_data=mock.Mock(side_effect=OSError('disk full')),
                    regenerate_page=mock.Mock(),
                    close_protocol_port=mock.Mock(return_value=True),
                )
                fn = extract_method(method_name, ns)
                code, _ = fn(_FakeHandler(b'action=disable'), '/tok/')
                self.assertEqual(code, 500)
                self.assertNotIn(cfg_key, data, f'回滚后仍残留脏键 {cfg_key}')

    def test_anytls_and_tuic_disable_rollback_still_restores_service_when_cfg_restore_fails(self):
        """AnyTLS/TUIC 停用 save_data 失败时，即便恢复配置文件抛 OSError，也必须继续恢复原服务状态。"""
        cases = [
            ('_h_post_manage_anytls', 'anytls_apply_lock', 'anytls_config',
             portal.ANYTLS_CONFIG_NAME, '_active_anytls_config'),
            ('_h_post_manage_tuic', 'tuic_apply_lock', 'tuic_config',
             portal.TUIC_CONFIG_NAME, '_active_tuic_config'),
        ]
        for method_name, lock_name, cfg_key, cfg_name, active_fn in cases:
            with self.subTest(method=method_name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / cfg_name).write_bytes(b'{"inbounds":[]}')
                restore_svc = mock.Mock(return_value=True)
                data = {cfg_key: {'enabled': True, 'port': 44555, 'domain': 'demo.example.com', 'secret': 's'}}
                ns = dict(
                    portal.__dict__,
                    data=data,
                    data_lock=threading.RLock(),
                    portal_path=root / 'portal.json',
                    save_data=mock.Mock(side_effect=OSError('disk full')),
                    regenerate_page=mock.Mock(),
                    close_protocol_port=mock.Mock(return_value=True),
                    _restore_config_atomically=mock.Mock(side_effect=OSError('ro fs')),
                    _restore_systemd_service_state=restore_svc,
                    _systemd_service_snapshot=mock.Mock(return_value={'active': 'active', 'enabled': 'enabled'}),
                    _systemd_state=mock.Mock(return_value='inactive'),
                    _service_stop_confirmed=mock.Mock(return_value=True),
                    subprocess=SimpleNamespace(run=mock.Mock(return_value=SimpleNamespace(returncode=0, stdout='', stderr=''))),
                )
                ns[lock_name] = threading.RLock()
                ns[active_fn] = lambda d=data, k=cfg_key: d[k]
                fn = extract_method(method_name, ns)
                code, payload = fn(_FakeHandler(b'action=disable'), '/tok/')
                self.assertEqual(code, 500)
                restore_svc.assert_called_once()
                self.assertIn('未能完整恢复', payload['error'])


if __name__ == '__main__':
    unittest.main()
