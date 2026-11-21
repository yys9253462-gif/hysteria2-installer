"""回归测试：入站代理管理控制字符拦截、回滚隔离 save_data 异常及 gost_written_ports 加锁更新。"""

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


class ProxyOperationRollbackAndControlsTests(unittest.TestCase):
    def _build_env(self, reload_side_effect, save_side_effect, fw_return=True):
        data = {'proxy_services': []}
        reload_mock = mock.Mock(side_effect=reload_side_effect)
        save_mock = mock.Mock(side_effect=save_side_effect)
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            gost_operation_lock=threading.RLock(),
            gost_owned=lambda: True,
            proxy_services=portal.proxy_services,
            read_meta_file=lambda _: {'public_ip': '198.51.100.1'},
            meta_path=Path('/tmp/client_meta.json'),
            portal_path=Path('/tmp/portal.json'),
            managed_reserved_ports=lambda *a, **kw: set(),
            _listening_ports=lambda: set(),
            save_data=save_mock,
            reload_gost=reload_mock,
            firewall_port=lambda *a, **kw: fw_return,
            protocol_port_in_use=lambda *a, **kw: False,
            _log_ignored=lambda *a, **kw: None,
        )
        real_path = Path

        class FakeGostBin:
            def exists(self):
                return True

        def fake_path(p):
            if str(p) == '/usr/local/bin/gost':
                return FakeGostBin()
            return real_path(p)

        ns['Path'] = fake_path
        fn = extract_method('_manage_proxy_operation', ns)
        return fn, data, reload_mock, save_mock

    def test_rejects_control_characters_in_username_or_password(self):
        """代理账号或密码含换行或控制字符时必须返回 400 拒绝。"""
        fn, data, reload_mock, save_mock = self._build_env([True], [None])
        for bad_params in (
            {'protocol': 'socks5', 'port': '15000', 'username': 'u\nbad', 'password': 'ok'},
            {'protocol': 'http', 'port': '15001', 'username': 'ok', 'password': 'p\r\nbad'},
            {'protocol': 'socks5', 'port': '15002', 'username': 'ok\x00x', 'password': 'ok'},
        ):
            with self.subTest(bad_params=bad_params):
                code, payload = fn(SimpleNamespace(), 'create', bad_params)
                self.assertEqual(code, 400, payload)
                self.assertFalse(payload['ok'])
        save_mock.assert_not_called()
        reload_mock.assert_not_called()
        self.assertEqual(data['proxy_services'], [])

    def test_reload_failure_rollback_still_reloads_gost_when_save_data_fails(self):
        """reload_gost 首次失败后，即使回滚 save_data 抛 OSError，也必须继续调用 reload_gost 还原运行配置。"""
        fn, data, reload_mock, _ = self._build_env(
            reload_side_effect=[False, True],
            save_side_effect=[None, OSError('disk full')],
        )
        code, payload = fn(SimpleNamespace(), 'create', {'protocol': 'socks5', 'port': '15010', 'username': 'u1', 'password': 'p1'})
        self.assertEqual(code, 500)
        self.assertFalse(payload['ok'])
        self.assertEqual(data['proxy_services'], [])
        self.assertEqual(reload_mock.call_count, 2, '回滚 save_data 失败后跳过了第二次 reload_gost')

    def test_firewall_failure_rollback_still_reloads_gost_when_save_data_fails(self):
        """防火墙放行失败后，即使回滚 save_data 抛 OSError，也必须继续调用 reload_gost 还原运行配置。"""
        fn, data, reload_mock, _ = self._build_env(
            reload_side_effect=[True, True],
            save_side_effect=[None, OSError('disk full')],
            fw_return=False,
        )
        code, payload = fn(SimpleNamespace(), 'create', {'protocol': 'socks5', 'port': '15011', 'username': 'u1', 'password': 'p1'})
        self.assertEqual(code, 500)
        self.assertFalse(payload['ok'])
        self.assertEqual(data['proxy_services'], [])
        self.assertEqual(reload_mock.call_count, 2, '防火墙失败回滚时 save_data 异常跳过了第二次 reload_gost')

    def test_write_gost_config_updates_written_ports_under_data_lock(self):
        """write_gost_config 更新 gost_written_ports 必须在 with data_lock: 块内完成。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        fn_src = src[src.index('    def write_gost_config():'):src.index('    def gost_ports_ready():')]
        # gost_written_ports[:] 赋值应与 with data_lock: 内循环同级缩进（12 格），而不是锁外 8 格
        self.assertIn('            gost_written_ports[:] = [int(s[\'addr\'].lstrip(\':\')) for s in services]', fn_src)


if __name__ == '__main__':
    unittest.main()
