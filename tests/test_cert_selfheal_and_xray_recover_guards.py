"""回归测试：证书运行态自愈容忍损坏状态文件、缺失显式证书不回退重载，以及启动恢复 Xray 容错。"""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class CertSelfhealAndXrayRecoverGuardsTests(unittest.TestCase):
    def test_sync_cert_runtime_recovers_when_state_file_is_corrupted(self):
        """cert-selfheal.json 损坏（坏 JSON / 非 UTF-8）时不得阻断证书运行态重载。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert_file = root / 'server.crt'
            cert_file.write_bytes(b'CERT-DATA-NEW')
            state_path = root / 'cert-selfheal.json'
            state_path.write_bytes(b'\xff\xfe{bad json')

            restarted = []

            def fake_run(cmd, **kwargs):
                restarted.append(cmd)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            with mock.patch.object(portal, '_systemd_state', side_effect=lambda s: 'active' if s == 'hysteria-server' else 'inactive'), \
                 mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                ok = portal.sync_cert_runtime(root, cert_file, state_path=state_path)

            self.assertTrue(ok)
            self.assertEqual(restarted, [['systemctl', 'try-restart', 'hysteria-server']])
            saved = json.loads(state_path.read_text(encoding='utf-8'))
            self.assertIn('loaded_cert_sha256', saved)

    def test_record_cert_heal_ignores_bool_or_negative_heal_count(self):
        """heal_count 被写坏成布尔值或负数时，record_cert_heal 应从 0 重新计数为 1。"""
        for bad_count in (True, -5):
            with self.subTest(bad_count=bad_count), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / 'cert-selfheal.json').write_text(json.dumps({'heal_count': bad_count}), encoding='utf-8')
                portal.record_cert_heal(root, None, {'pin_sha256': 'a'}, {'pin_sha256': 'b'})
                saved = json.loads((root / 'cert-selfheal.json').read_text(encoding='utf-8'))
                self.assertEqual(saved['heal_count'], 1)

    def test_selfheal_skips_runtime_reload_when_configured_cert_missing(self):
        """config.yaml 显式指向不存在的证书时，selfheal 不得回退拿旧 cert/server.crt 触发 sync_cert_runtime。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'cert').mkdir()
            (root / 'cert' / 'server.crt').write_bytes(b'OLD-SELF-SIGNED')
            cfg = root / 'config.yaml'
            cfg.write_text('tls:\n  cert: /nonexistent/path/live.crt\n  key: /nonexistent/path/live.key\n', encoding='utf-8')
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({'server_name': 'example.com'}), encoding='utf-8')

            with mock.patch.object(portal, 'sync_cert_runtime') as rt_mock, \
                 mock.patch.object(portal, 'sync_pin'):
                portal.selfheal(meta, config_path=cfg)
            rt_mock.assert_not_called()

    def test_recover_xray_handles_null_settings_and_systemctl_timeout(self):
        """xray.json 单入站 settings=null 不得清空其它入站；systemctl 异常不得打断门户启动。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'xray.json'
            cfg.write_text(json.dumps({
                'inbounds': [
                    {'tag': portal.REALITY_INBOUND_TAG, 'settings': None},
                    {'tag': portal.VMESS_INBOUND_TAG, 'settings': {'clients': [{'id': 'old'}]}},
                ]
            }), encoding='utf-8')
            data = {'users': {}}
            lock = threading.RLock()
            apply_called = []

            def fake_run(cmd, **kwargs):
                if cmd[1] == 'reset-failed':
                    raise OSError('systemctl missing')
                if cmd[1] == 'restart':
                    raise subprocess.TimeoutExpired(cmd, 10)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            note = portal.recover_xray_service_on_start(
                data, lock,
                apply_access=lambda: (apply_called.append(True) or True),
                suspended=lambda unit: False,
                config_path=cfg,
                run=fake_run,
                systemd_state=lambda unit: 'inactive',
                sleep=lambda _: None,
            )
            self.assertTrue(apply_called, 'settings=null 不应导致整个托管入站集合被清空跳过同步')
            self.assertIn('失败', note)


if __name__ == '__main__':
    unittest.main()
