"""回归测试：apply_xray_config_transaction 容忍初始状态探测超时、隔离 reset-failed 异常并使用 O_NOFOLLOW 私有写入。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class XrayTransactionPreflightAndNofollowTests(unittest.TestCase):
    def test_initial_state_probe_timeout_and_reset_failed_timeout_do_not_break_apply(self):
        """初始 is-enabled/is-active 探测或重启前 reset-failed 超时时，不应阻断正常配置预检与重启。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'xray.json'
            cfg.write_text('{"inbounds":[]}', encoding='utf-8')
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                if cmd[:2] == ['systemctl', 'is-enabled']:
                    raise subprocess.TimeoutExpired(cmd, 5)
                if cmd[:2] == ['systemctl', 'reset-failed']:
                    raise subprocess.TimeoutExpired(cmd, 5)
                if cmd[:2] == ['systemctl', 'is-active']:
                    return SimpleNamespace(returncode=0, stdout='active\n', stderr='')
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                portal.apply_xray_config_transaction({'inbounds': [{'tag': 'a'}]}, config_path=str(cfg), enable=False)

            self.assertEqual(json.loads(cfg.read_text(encoding='utf-8')), {'inbounds': [{'tag': 'a'}]})
            self.assertIn(['systemctl', 'restart', 'xray'], calls)

    def test_rollback_reset_failed_timeout_still_attempts_restart(self):
        """回滚阶段 reset-failed 超时时，不得跳过随后的 systemctl restart xray。"""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'xray.json'
            cfg.write_text('{"old":1}', encoding='utf-8')
            restart_count = [0]
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                if cmd[:2] == ['systemctl', 'is-active']:
                    return SimpleNamespace(returncode=0, stdout='active\n', stderr='')
                if cmd[:2] == ['systemctl', 'is-enabled']:
                    return SimpleNamespace(returncode=0, stdout='enabled\n', stderr='')
                if cmd[:2] == ['systemctl', 'restart']:
                    restart_count[0] += 1
                    return SimpleNamespace(returncode=1 if restart_count[0] == 1 else 0, stdout='', stderr='boom')
                if cmd[:2] == ['systemctl', 'reset-failed'] and restart_count[0] >= 1:
                    raise subprocess.TimeoutExpired(cmd, 5)
                return SimpleNamespace(returncode=0, stdout='', stderr='')

            with mock.patch.object(portal.subprocess, 'run', side_effect=fake_run):
                with self.assertRaises(RuntimeError):
                    portal.apply_xray_config_transaction({'new': 2}, config_path=str(cfg), enable=False)

            self.assertEqual(restart_count[0], 2, f'回滚 reset-failed 超时导致跳过恢复重启: {calls}')
            self.assertEqual(json.loads(cfg.read_text(encoding='utf-8')), {'old': 1})

    def test_write_priv_uses_o_nofollow(self):
        """apply_xray_config_transaction 内的 _write_priv 必须使用 O_NOFOLLOW 防止符号链接覆写。"""
        src = (ROOT / 'portal.py').read_text(encoding='utf-8')
        s = src.index('def apply_xray_config_transaction(')
        e = src.index('def set_outbound_apply_error(', s)
        self.assertIn('O_NOFOLLOW', src[s:e])


if __name__ == '__main__':
    unittest.main()
