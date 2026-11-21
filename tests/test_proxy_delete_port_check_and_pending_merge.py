"""回归测试：删除代理回收防火墙不得忽略其余仍在运行的同端口代理、创建代理跳过布尔端口及非对象 xray.json，以及 apply_access 回滚保留并发新增待撤销项。"""

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


class ProxyDeletePortCheckAndPendingMergeTests(unittest.TestCase):
    def test_delete_proxy_does_not_close_firewall_when_another_proxy_still_uses_port(self):
        """删除代理时 data_snapshot 已剔除被删条目，不得用 exclude_key='proxy_services' 跳过其余同端口代理。"""
        data = {
            'proxy_services': [
                {'id': 'p1', 'type': 'socks5', 'port': 15555, 'username': 'u1', 'password': 'x1'},
                {'id': 'p2', 'type': 'http', 'port': 15555, 'username': 'u2', 'password': 'x2'},
            ]
        }
        fw_calls = []

        class FakeGostBin:
            def exists(self):
                return True

        real_path = Path

        def fake_path(p):
            if str(p) == '/usr/local/bin/gost':
                return FakeGostBin()
            return real_path(p)

        ns = dict(
            portal.__dict__,
            Path=fake_path,
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
            save_data=lambda: None,
            reload_gost=lambda: True,
            firewall_port=lambda *a, **kw: (fw_calls.append((a, kw)) or True),
            protocol_port_in_use=portal.protocol_port_in_use,
            _log_ignored=lambda *a, **kw: None,
        )
        fn = extract_method('_manage_proxy_operation', ns)
        with mock.patch.object(portal, '_systemd_state', return_value='inactive'):
            code, payload = fn(SimpleNamespace(), 'delete', {'id': 'p1'})
        self.assertEqual(code, 200, payload)
        self.assertEqual(fw_calls, [], '其余同端口代理仍在运行时不应关闭该端口防火墙')

    def test_create_proxy_ignores_bool_existing_port_and_non_dict_xray_json(self):
        """历史 proxy_services 含布尔端口、xray.json 为非 JSON 对象时创建代理应正常成功。"""
        with tempfile.TemporaryDirectory() as td:
            xray_file = Path(td) / 'xray.json'
            xray_file.write_text('["not-an-object"]', encoding='utf-8')
            seen_cfg = []

            class FakeGostBin:
                def exists(self):
                    return True

            real_path = Path

            def fake_path(p):
                if str(p) == '/usr/local/bin/gost':
                    return FakeGostBin()
                if str(p) == '/etc/hysteria/xray.json':
                    return xray_file
                return real_path(p)

            data = {'proxy_services': [{'id': 'bad', 'type': 'socks5', 'port': True}]}
            ns = dict(
                portal.__dict__,
                Path=fake_path,
                data=data,
                data_lock=threading.RLock(),
                gost_operation_lock=threading.RLock(),
                gost_owned=lambda: True,
                proxy_services=portal.proxy_services,
                read_meta_file=lambda _: {'public_ip': '198.51.100.1'},
                meta_path=Path(td) / 'client_meta.json',
                portal_path=Path(td) / 'portal.json',
                managed_reserved_ports=lambda m, d, cfg, **kw: (seen_cfg.append(cfg) or set()),
                _listening_ports=lambda: set(),
                save_data=lambda: None,
                reload_gost=lambda: True,
                firewall_port=lambda *a, **kw: True,
                protocol_port_in_use=lambda *a, **kw: False,
                _log_ignored=lambda *a, **kw: None,
            )
            fn = extract_method('_manage_proxy_operation', ns)
            code, payload = fn(SimpleNamespace(), 'create', {
                'protocol': 'socks5', 'port': '15556', 'username': 'u1', 'password': 'p1'
            })
            self.assertEqual(code, 200, payload)
            self.assertEqual(seen_cfg, [None], '非 JSON 对象的 xray.json 不得原样传给 managed_reserved_ports')

    def test_apply_access_rollback_preserves_concurrently_added_pending_revocations(self):
        """apply_access 写盘 OSError 回滚 _pending_revocations 时必须合并锁外并发新增的待撤销用户。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        start = src.index('    def apply_access(')
        end = src.index('    def expiry_access_worker():', start)
        body = src[start:end]
        self.assertIn("data['_pending_revocations'] = sorted(pending_revocations(data) | previous_pending | pending)", body)


if __name__ == '__main__':
    unittest.main()
