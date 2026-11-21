"""回归测试：AnyTLS / TUIC 启用失败回滚中 daemon-reload 失败不得跳过服务状态恢复，且单元写入原子化。"""

import copy
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


class AnytlsTuicRollbackIsolationTests(unittest.TestCase):
    def _make_base_ns(self, root: Path):
        real_path = Path

        def fake_path(value):
            s = str(value)
            if s.startswith('/etc/systemd/system/'):
                return real_path(root / s.lstrip('/'))
            return real_path(value)

        return dict(
            portal.__dict__,
            Path=fake_path,
            data={},
            data_lock=threading.RLock(),
            portal_path=root / 'etc/hysteria/portal.json',
            meta_path=root / 'etc/hysteria/client_meta.json',
            _log_ignored=lambda *a, **kw: None,
        )

    def test_anytls_rollback_still_restores_service_when_daemon_reload_fails(self):
        """AnyTLS 启用失败回滚时，即使回滚 daemon-reload 超时也必须继续调用 _restore_systemd_service_state。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'etc/hysteria').mkdir(parents=True)
            (root / 'etc/systemd/system').mkdir(parents=True)
            ns = self._make_base_ns(root)
            orig_cfg = {'enabled': False, 'port': 2096, 'secret': 'fixture'}
            ns['data']['anytls_config'] = copy.deepcopy(orig_cfg)
            restore_svc = mock.Mock(return_value=True)
            ns.update({
                'ANYTLS_SERVICE': 'hy2-anytls',
                'ANYTLS_CONFIG_NAME': portal.ANYTLS_CONFIG_NAME,
                'ANYTLS_UNIT_CONTENT': portal.ANYTLS_UNIT_CONTENT,
                'anytls_apply_lock': threading.RLock(),
                'read_meta_file': lambda _: {'server_name': 'node.example.com'},
                '_is_dns_name': lambda _: True,
                '_singbox_version': lambda: portal.ANYTLS_MIN_SINGBOX,
                'managed_reserved_ports': lambda *a, **kw: set(),
                '_pick_reality_port': lambda **kw: (2096, ''),
                '_systemd_state': lambda _: 'inactive',
                'anytls_users': lambda _: [],
                'build_anytls_config': lambda *a: {},
                'apply_anytls_config': mock.Mock(),
                '_systemd_service_snapshot': lambda _: {'active': 'inactive', 'enabled': 'disabled'},
                '_restore_systemd_service_state': restore_svc,
                'save_data': mock.Mock(side_effect=OSError('disk full')),
                'config_section': lambda data, key: data.get(key, {}),
            })
            reload_calls = [0]

            def flaky_run(args, **kwargs):
                if args == ['systemctl', 'daemon-reload']:
                    reload_calls[0] += 1
                    if reload_calls[0] == 2:
                        raise subprocess.TimeoutExpired(args, 30)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            ns['subprocess'] = SimpleNamespace(run=flaky_run, SubprocessError=subprocess.SubprocessError)
            handler = SimpleNamespace(_vmess_certificate=lambda *a: ('cert.pem', 'key.pem', 'node.example.com'))
            with mock.patch.object(portal.subprocess, 'run', side_effect=flaky_run):
                with self.assertRaisesRegex(RuntimeError, 'AnyTLS 启用失败，且原服务状态未能完整恢复'):
                    extract_method('_apply_anytls_enable', ns)(handler)

            restore_svc.assert_called_once_with('hy2-anytls', {'active': 'inactive', 'enabled': 'disabled'})
            self.assertEqual(ns['data']['anytls_config'], orig_cfg)

    def test_tuic_rollback_still_restores_service_when_daemon_reload_fails(self):
        """TUIC 启用失败回滚时，即使回滚 daemon-reload 返回非零也必须继续调用 _restore_systemd_service_state。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'etc/hysteria').mkdir(parents=True)
            (root / 'etc/systemd/system').mkdir(parents=True)
            ns = self._make_base_ns(root)
            orig_cfg = {'enabled': False, 'port': 41000, 'secret': 'fixture'}
            ns['data']['tuic_config'] = copy.deepcopy(orig_cfg)
            restore_svc = mock.Mock(return_value=True)
            ns.update({
                'TUIC_SERVICE': 'hy2-tuic',
                'TUIC_CONFIG_NAME': portal.TUIC_CONFIG_NAME,
                'TUIC_UNIT_CONTENT': portal.TUIC_UNIT_CONTENT,
                'tuic_apply_lock': threading.RLock(),
                'read_meta_file': lambda _: {'server_name': 'node.example.com', 'listen_port': 443},
                '_is_dns_name': lambda _: True,
                '_singbox_version': lambda: portal.ANYTLS_MIN_SINGBOX,
                'pick_tuic_port': lambda *a, **kw: 41001,
                'tuic_users': lambda _: [],
                'build_tuic_config': lambda *a: {},
                'apply_anytls_config': mock.Mock(),
                '_systemd_state': lambda _: 'inactive',
                '_systemd_service_snapshot': lambda _: {'active': 'inactive', 'enabled': 'disabled'},
                '_restore_systemd_service_state': restore_svc,
                'save_data': mock.Mock(side_effect=OSError('disk full')),
                'config_section': lambda data, key: data.get(key, {}),
            })
            reload_calls = [0]

            def flaky_run(args, **kwargs):
                if args == ['systemctl', 'daemon-reload']:
                    reload_calls[0] += 1
                    if reload_calls[0] == 2:
                        raise subprocess.CalledProcessError(1, args)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            ns['subprocess'] = SimpleNamespace(run=flaky_run, SubprocessError=subprocess.SubprocessError)
            handler = SimpleNamespace(_vmess_certificate=lambda *a: ('cert.pem', 'key.pem', 'node.example.com'))
            with mock.patch.object(portal.subprocess, 'run', side_effect=flaky_run):
                with self.assertRaisesRegex(RuntimeError, 'TUIC 启用失败，且原服务状态未能完整恢复'):
                    extract_method('_apply_tuic_enable', ns)(handler)

            restore_svc.assert_called_once_with('hy2-tuic', {'active': 'inactive', 'enabled': 'disabled'})
            self.assertEqual(ns['data']['tuic_config'], orig_cfg)

    def test_anytls_and_tuic_enable_do_not_overwrite_unit_with_bare_write_text(self):
        """AnyTLS 与 TUIC 写入 systemd 单元不得使用裸 write_text 覆写。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        anytls_fn = src[src.index('        def _apply_anytls_enable('):src.index('        def _h_post_manage_anytls(')]
        tuic_fn = src[src.index('        def _apply_tuic_enable('):src.index('        def _h_post_manage_tuic(')]
        self.assertNotIn('unit_path.write_text(', anytls_fn)
        self.assertNotIn('unit_path.write_text(', tuic_fn)


if __name__ == '__main__':
    unittest.main()
