"""核心准入同步回滚恢复原权限并在重启前清理失败计数。

旧实现在回滚写回原配置时重建临时文件未恢复原文件权限，导致权限退化为默认掩码；
同时回滚重启前未清理失败计数，撞上启动频率上限时回滚重启会被拒绝。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


class XrayAccessRollbackTests(unittest.TestCase):
    def test_rollback_restores_mode_and_resets_failed_before_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xj = root / 'xray.json'
            orig_cfg = {
                'inbounds': [
                    {
                        'tag': portal.REALITY_INBOUND_TAG,
                        'settings': {'clients': [{'id': 'old', 'email': 'u1'}]},
                    }
                ]
            }
            original = json.dumps(orig_cfg).encode('utf-8')
            xj.write_bytes(original)
            if os.name != 'nt':
                os.chmod(xj, 0o600)
            orig_mode = xj.stat().st_mode & 0o777

            calls = []
            chmod_modes = []
            real_chmod = Path.chmod
            restarts = 0

            def spy_chmod(self_path, mode, *args, **kwargs):
                chmod_modes.append((self_path.name, mode))
                return real_chmod(self_path, mode, *args, **kwargs)

            def fake_run(args, **kwargs):
                nonlocal restarts
                calls.append(list(args))
                if args[:2] == ['systemctl', 'show']:
                    return SimpleNamespace(returncode=0, stdout='epoch-1\n', stderr='')
                if args[:2] == ['systemctl', 'is-active']:
                    return SimpleNamespace(returncode=0, stdout='active\n', stderr='')
                if args[:2] == ['systemctl', 'restart']:
                    restarts += 1
                    if restarts == 1:
                        raise subprocess.CalledProcessError(1, args)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            wanted = {portal.REALITY_INBOUND_TAG: [{'id': 'new', 'email': 'u2'}]}
            with patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                    patch.object(Path, 'chmod', spy_chmod):
                with self.assertRaises(subprocess.CalledProcessError):
                    portal._apply_xray_access_snapshot_locked(
                        root, xj, {}, {'u1'}, root / 'usage-meter-config.json',
                        {'reality': {'binary': 'xray'}}, (), wanted
                    )

            self.assertEqual(xj.read_bytes(), original)
            # 正常替换前一次，回滚替换前一次，均必须恢复原权限
            self.assertEqual(len(chmod_modes), 2, chmod_modes)
            self.assertEqual(chmod_modes[-1][1], orig_mode)
            if os.name != 'nt':
                self.assertEqual(xj.stat().st_mode & 0o777, 0o600)
            # 回滚重启之前必须先执行一次失败计数清理
            self.assertEqual(calls[-2:], [
                ['systemctl', 'reset-failed', 'xray'],
                ['systemctl', 'restart', 'xray'],
            ])


if __name__ == '__main__':
    unittest.main()
