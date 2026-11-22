"""回归测试：apply_egress_config、_restore_config_atomically、apply_anytls_config、sync_anytls_users、sync_tuic_users 与 _generate_and_apply_reality 的符号链接/体积上限、随机候选文件、回滚异常隔离及脏计量配置防护。"""

import ast
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import portal

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class TestPortalEgressAnytlsTuicSyncAndRealityApplyGuards(unittest.TestCase):
    def test_apply_egress_config_rejects_oversized_and_isolates_unlink_oserror(self):
        """apply_egress_config 必须拒绝超过 4 MiB 的异常配置，且 finally 清理 OSError 不得掩盖原始异常。"""
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / 'config.yaml'
            big.write_bytes(b'a' * (4 * 1024 * 1024 + 16))
            ok, err = portal.apply_egress_config({}, threading.RLock(), config_path=str(big))
            self.assertFalse(ok)
            self.assertIn('上限', err)

            cfg = Path(td) / 'ok.yaml'
            cfg.write_text('listen: :443\n', encoding='utf-8')
            with mock.patch.object(portal, '_hy2_runtime_identity', return_value=('active', '100', '1')), \
                 mock.patch.object(portal, '_hy2_config_loaded', return_value=False), \
                 mock.patch.object(portal.os, 'replace', side_effect=PermissionError('disk-readonly')), \
                 mock.patch.object(portal.os, 'unlink', side_effect=OSError('unlink-boom')):
                ok2, err2 = portal.apply_egress_config({}, threading.RLock(), config_path=str(cfg))
            self.assertFalse(ok2)
            self.assertIn('disk-readonly', err2, f'finally unlink 异常掩盖了原始错误: {err2}')

    def test_restore_config_atomically_tolerates_dir_fsync_and_cleanup_errors(self):
        """_restore_config_atomically 在目录 fsync 抛 OSError 时不得误报回滚失败，且清理失败不得掩盖原始异常。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'anytls.json'
            cfg.write_bytes(b'old')
            real_fsync = os.fsync
            calls = {'n': 0}

            def flaky_fsync(fd):
                calls['n'] += 1
                if calls['n'] >= 2:
                    raise OSError('EINVAL on dir fsync')
                return real_fsync(fd)

            with mock.patch.object(portal.os, 'fsync', side_effect=flaky_fsync):
                portal._restore_config_atomically(cfg, b'restored')
            self.assertEqual(cfg.read_bytes(), b'restored')

            with mock.patch.object(portal.os, 'replace', side_effect=RuntimeError('orig-replace-err')), \
                 mock.patch.object(Path, 'unlink', side_effect=OSError('unlink-err')):
                with self.assertRaisesRegex(RuntimeError, 'orig-replace-err'):
                    portal._restore_config_atomically(cfg, b'again')

    def test_apply_anytls_config_validates_service_uses_random_candidate_and_caps_size(self):
        """apply_anytls_config 必须拒绝非法 service 名、使用随机后缀候选文件名并拒绝超过 4 MiB 原配置。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'anytls.json'
            with self.assertRaises(ValueError):
                portal.apply_anytls_config({'inbounds': []}, cfg, restart=False, service='--evil')
            with self.assertRaises(ValueError):
                portal.apply_anytls_config({'inbounds': []}, cfg, restart=False, service='svc\nbad')

            seen_paths = []

            def fake_run(cmd, **kw):
                if 'check' in cmd:
                    seen_paths.append(cmd[-1])
                return mock.Mock(returncode=0)

            portal.apply_anytls_config({'inbounds': []}, cfg, restart=False, run=fake_run)
            self.assertEqual(len(seen_paths), 1)
            self.assertNotEqual(Path(seen_paths[0]).name, 'anytls.candidate.json',
                                '候选文件必须带随机后缀防止固定名竞态')

            big = Path(td) / 'big.json'
            big.write_bytes(b'x' * (4 * 1024 * 1024 + 8))
            with self.assertRaises(ValueError):
                portal.apply_anytls_config({'inbounds': []}, big, restart=False, run=fake_run)

    def test_sync_anytls_and_tuic_users_reject_oversized_config(self):
        """sync_anytls_users 与 sync_tuic_users 读取超 4 MiB 合法配置文件必须报 RuntimeError 拒绝无界读盘。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pad = 'a' * (4 * 1024 * 1024 + 16)
            (root / portal.ANYTLS_CONFIG_NAME).write_text(
                json.dumps({'inbounds': [{'tag': portal.ANYTLS_INBOUND_TAG, 'users': []}], 'pad': pad}),
                encoding='utf-8',
            )
            (root / portal.TUIC_CONFIG_NAME).write_text(
                json.dumps({'inbounds': [{'tag': portal.TUIC_INBOUND_TAG, 'users': []}], 'pad': pad}),
                encoding='utf-8',
            )
            snap = {
                'anytls_config': {'enabled': True, 'secret': 's'},
                'tuic_config': {'enabled': True, 'secret': 's'},
                'users': {},
            }
            with self.assertRaisesRegex(RuntimeError, 'unreadable|上限|symlink'):
                portal.sync_anytls_users(root, snap, apply=lambda *a, **k: None, service_active=lambda: False)
            with self.assertRaisesRegex(RuntimeError, 'unreadable|上限|symlink'):
                portal.sync_tuic_users(root, snap, apply=lambda *a, **k: None, service_active=lambda: False)

    def test_generate_and_apply_reality_guards_inf_port_and_corrupt_meter_config(self):
        """_generate_and_apply_reality 不得对旧端口裸调 int()，且须校验计量配置字典/地址字符串及 loader 判空。"""
        tree = ast.parse(PORTAL_SRC)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == '_generate_and_apply_reality':
                src = ast.get_source_segment(PORTAL_SRC, node)
                self.assertNotIn("_old_port = int(rcfg_old.get('port'))", src,
                                 '对 float("inf") 旧端口裸调 int() 会抛未捕获 OverflowError')
                self.assertIn('isinstance(_meter_config, dict)', src)
                self.assertIn('isinstance(_meter_reality, dict)', src)
                self.assertIn('isinstance(_address, str)', src)
                self.assertIn('_stats_spec is None or _stats_spec.loader is None', src)
                return
        self.fail('未找到 _generate_and_apply_reality')


if __name__ == '__main__':
    unittest.main()
