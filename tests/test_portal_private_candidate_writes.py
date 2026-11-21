"""回归测试：门户写入 Xray / AnyTLS / TUIC 敏感候选配置与备份必须直接私有创建且失败不残留。"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class PortalPrivateCandidateWritesTests(unittest.TestCase):
    def test_apply_anytls_config_cleans_candidate_when_chmod_fails(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'anytls.json'
            with mock.patch.object(portal.os, 'chmod', side_effect=PermissionError('chmod denied')):
                with self.assertRaises(PermissionError):
                    portal.apply_anytls_config({'inbounds': []}, cfg, restart=False)
            leftovers = [p.name for p in Path(td).iterdir() if 'candidate' in p.name]
            self.assertEqual(leftovers, [], f'apply_anytls_config 失败后残留候选配置: {leftovers}')

    def test_apply_xray_config_transaction_rollback_timeout_preserves_original_error(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'xray.json'
            cfg.write_text('{"old": true}', encoding='utf-8')
            restart_count = {'n': 0}

            def fake_run(args, **kwargs):
                if args[:2] == ['systemctl', 'is-active']:
                    return SimpleNamespace(returncode=0, stdout='active')
                if args[:2] == ['systemctl', 'is-enabled']:
                    return SimpleNamespace(returncode=0, stdout='enabled')
                if args[:3] == ['/usr/local/bin/xray', 'run', '-test']:
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                if args[:2] == ['systemctl', 'restart']:
                    restart_count['n'] += 1
                    if restart_count['n'] == 1:
                        return SimpleNamespace(returncode=1, stdout='', stderr='start failed')
                    raise subprocess.TimeoutExpired(args, 15)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, 'Xray 启动失败'):
                    portal.apply_xray_config_transaction({'new': True}, config_path=str(cfg))
            self.assertEqual(cfg.read_text(encoding='utf-8'), '{"old": true}')

    def test_apply_xray_access_snapshot_cleans_candidate_when_chmod_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xj = root / 'xray.json'
            xcfg = {
                'inbounds': [{
                    'tag': portal.REALITY_INBOUND_TAG,
                    'protocol': 'vless',
                    'settings': {'clients': [{'id': 'old-id', 'email': 'u1'}]},
                }]
            }
            xj.write_text(json.dumps(xcfg), encoding='utf-8')
            snapshot = {'users': {'u1': {'password': 'p1', 'status': 'active'}}, 'reality_config': {'enabled': True}}

            def fake_run(args, **kwargs):
                if args[:2] == ['systemctl', 'show']:
                    return SimpleNamespace(returncode=0, stdout='ep-1\n')
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            wanted = {portal.REALITY_INBOUND_TAG: [{'id': 'new-id', 'email': 'u1'}]}
            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(portal.os, 'chmod', side_effect=PermissionError('chmod denied')):
                with self.assertRaises(PermissionError):
                    portal._apply_xray_access_snapshot_locked(
                        root, xj, snapshot, False, root / 'meter.json', {}, ('u1',), wanted
                    )
            leftovers = [p.name for p in root.iterdir() if 'candidate' in p.name]
            self.assertEqual(leftovers, [], f'_apply_xray_access_snapshot_locked 失败后残留候选配置: {leftovers}')

    def test_no_default_umask_candidate_writes_in_sensitive_config_paths(self):
        src = (Path(__file__).resolve().parents[1] / 'portal.py').read_text(encoding='utf-8')
        self.assertNotIn("candidate.write_text(json.dumps(config, indent=2), encoding='utf-8')", src)
        self.assertNotIn("candidate.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding='utf-8')", src)
        self.assertNotIn("candidate.write_text(json.dumps(xcfg,indent=2),encoding='utf-8')", src)
        self.assertNotIn("shutil.copy2(xj,xj.with_name('xray.expiry-last-good.json'))", src)


if __name__ == '__main__':
    unittest.main()
