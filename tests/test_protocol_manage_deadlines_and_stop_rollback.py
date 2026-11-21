"""回归测试：五大协议启停接口补齐连接死线续期，AnyTLS/TUIC 停用对齐核心锁序并在停服超时时回滚服务状态。"""

import contextlib
import io
import subprocess
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


class ProtocolManageDeadlinesAndStopRollbackTests(unittest.TestCase):
    def test_five_protocol_manage_handlers_extend_deadline(self):
        """Reality/VMess/VLESS Encryption/AnyTLS/TUIC 启停处理器均须延长连接死线避免 30 秒截断。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        pairs = (
            ('def _h_post_manage_reality(self, prefix):', 'def _h_get_reality_status('),
            ('def _h_post_manage_vmess(self, prefix):', 'def _h_get_vmess_status('),
            ('def _h_post_manage_anytls(self, prefix):', 'def _h_get_anytls_status('),
            ('def _h_post_manage_tuic(self, prefix):', 'def _h_get_tuic_status('),
            ('def _h_post_manage_vlessenc(self, prefix):', 'def _h_get_vlessenc_status('),
        )
        for start_sig, end_sig in pairs:
            with self.subTest(handler=start_sig):
                s = src.index(start_sig)
                e = src.index(end_sig, s)
                self.assertIn('_extend_deadline(120)', src[s:e])

    def test_anytls_and_tuic_disable_hold_core_lock_and_rollback_on_stop_timeout(self):
        """AnyTLS/TUIC 停用必须持核心锁并在 systemctl disable --now 超时时恢复原服务状态。"""
        cases = (
            ('_h_post_manage_anytls', 'anytls_apply_lock', 'anytls_config',
             portal.ANYTLS_CONFIG_NAME, portal.ANYTLS_SERVICE, '_active_anytls_config'),
            ('_h_post_manage_tuic', 'tuic_apply_lock', 'tuic_config',
             portal.TUIC_CONFIG_NAME, portal.TUIC_SERVICE, '_active_tuic_config'),
        )
        for method_name, lock_name, cfg_key, cfg_file, svc_name, active_fn in cases:
            with self.subTest(method=method_name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg_path = root / cfg_file
                cfg_path.write_text('{}', encoding='utf-8')
                core_lock_entered = []
                restore_mock = mock.Mock(return_value=True)
                extended = []

                @contextlib.contextmanager
                def track_core_lock():
                    core_lock_entered.append(True)
                    yield

                def timeout_run(cmd, **kwargs):
                    raise subprocess.TimeoutExpired(cmd, 30)

                data = {cfg_key: {'enabled': True, 'port': 44600, 'domain': 'demo.example.com', 'secret': 's'}}
                ns = dict(
                    portal.__dict__,
                    data=data,
                    data_lock=threading.RLock(),
                    core_operation_lock=track_core_lock(),
                    core_operation_file_lock=lambda: contextlib.nullcontext(),
                    portal_path=root / 'portal.json',
                    save_data=mock.Mock(),
                    regenerate_page=mock.Mock(),
                    close_protocol_port=mock.Mock(return_value=True),
                    _restore_systemd_service_state=restore_mock,
                    _systemd_service_snapshot=mock.Mock(return_value={'active': 'active', 'enabled': 'enabled'}),
                    _systemd_state=mock.Mock(return_value='active'),
                    _service_stop_confirmed=mock.Mock(return_value=False),
                    subprocess=SimpleNamespace(run=timeout_run, SubprocessError=subprocess.SubprocessError),
                )
                ns[lock_name] = threading.RLock()
                ns[active_fn] = lambda: data[cfg_key]

                replies = []
                body = b'action=disable'
                handler = SimpleNamespace(
                    is_authenticated=lambda: True,
                    _extend_deadline=lambda sec: extended.append(sec),
                    headers={'Content-Length': str(len(body))},
                    rfile=io.BytesIO(body),
                    reply_json=lambda code, payload: replies.append((code, payload)),
                )
                extract_method(method_name, ns)(handler, '/tok/')

                self.assertEqual(replies[-1][0], 500)
                self.assertTrue(extended, f'{method_name} 未调用 _extend_deadline')
                self.assertTrue(core_lock_entered, f'{method_name} 停用分支未持有 core_operation_lock')
                restore_mock.assert_called_once_with(svc_name, {'active': 'active', 'enabled': 'enabled'})
                self.assertTrue(cfg_path.exists(), '停服超时时不得删除配置文件')


if __name__ == '__main__':
    unittest.main()
