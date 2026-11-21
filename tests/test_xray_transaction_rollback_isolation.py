"""回归测试：apply_xray_config_transaction 回滚写盘失败不掩盖原异常，且 enable/disable 超时不跳过 restart/stop。"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class XrayTransactionRollbackIsolationTests(unittest.TestCase):
    def test_enable_timeout_during_rollback_still_attempts_restart(self):
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text('{"inbounds": []}', encoding='utf-8')
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                if cmd[:2] == ['systemctl', 'is-active']:
                    # 初次检查在运行；重启后返回 inactive 触发回滚
                    n = sum(1 for c in calls if c[:2] == ['systemctl', 'is-active'])
                    return subprocess.CompletedProcess(cmd, 0, 'active\n' if n == 1 else 'inactive\n', '')
                if cmd[:2] == ['systemctl', 'is-enabled']:
                    return subprocess.CompletedProcess(cmd, 0, 'enabled\n', '')
                if cmd[:2] == ['systemctl', 'enable']:
                    raise subprocess.TimeoutExpired(cmd, 15)
                return subprocess.CompletedProcess(cmd, 0, '', '')

            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, 'Xray 启动失败'):
                    portal.apply_xray_config_transaction({'inbounds': [{'tag': 'x'}]}, str(cfg_path))

            restarts = [c for c in calls if c[:2] == ['systemctl', 'restart']]
            self.assertEqual(len(restarts), 2, f'回滚 enable 超时后跳过了第二次 restart: {calls}')

    def test_config_restore_oserror_does_not_mask_original_error_or_skip_service_restore(self):
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / 'xray.json'
            cfg_path.write_text('{"inbounds": []}', encoding='utf-8')
            calls = []
            real_replace = portal.os.replace
            replace_count = {'n': 0}

            def flaky_replace(src, dst):
                replace_count['n'] += 1
                if replace_count['n'] >= 2:
                    raise OSError('disk read-only during rollback')
                return real_replace(src, dst)

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                if cmd[:2] == ['systemctl', 'is-active']:
                    n = sum(1 for c in calls if c[:2] == ['systemctl', 'is-active'])
                    return subprocess.CompletedProcess(cmd, 0, 'active\n' if n == 1 else 'inactive\n', '')
                if cmd[:2] == ['systemctl', 'is-enabled']:
                    return subprocess.CompletedProcess(cmd, 0, 'enabled\n', '')
                return subprocess.CompletedProcess(cmd, 0, '', '')

            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run), \
                 mock.patch.object(portal.os, 'replace', side_effect=flaky_replace):
                with self.assertRaisesRegex(RuntimeError, 'Xray 启动失败'):
                    portal.apply_xray_config_transaction({'inbounds': [{'tag': 'x'}]}, str(cfg_path))

            restarts = [c for c in calls if c[:2] == ['systemctl', 'restart']]
            self.assertEqual(len(restarts), 2, f'回滚写盘失败后跳过了服务恢复: {calls}')


if __name__ == '__main__':
    unittest.main()
