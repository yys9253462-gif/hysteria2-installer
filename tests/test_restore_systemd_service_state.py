"""回归测试：_restore_systemd_service_state 恢复 active 服务前清理失败计数并执行 restart。"""
import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('portal_restore_svc_test', ROOT / 'portal.py')
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)


class RestoreSystemdServiceStateTests(unittest.TestCase):
    def test_restoring_active_service_resets_failed_and_restarts(self):
        calls = []
        state = {'active': 'failed', 'enabled': 'enabled', 'limit_hit': True}

        def fake_run(args, **kwargs):
            calls.append(list(args))
            if args[:2] == ['systemctl', 'is-active']:
                return SimpleNamespace(returncode=0, stdout=state['active'])
            if args[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0, stdout=state['enabled'])
            if args[:2] == ['systemctl', 'reset-failed']:
                state['limit_hit'] = False
                return SimpleNamespace(returncode=0, stdout='')
            if args[:2] == ['systemctl', 'restart']:
                if state['limit_hit']:
                    return SimpleNamespace(returncode=1, stdout='')
                state['active'] = 'active'
                return SimpleNamespace(returncode=0, stdout='')
            if args[:2] == ['systemctl', 'start']:
                if state['limit_hit']:
                    return SimpleNamespace(returncode=1, stdout='')
                state['active'] = 'active'
                return SimpleNamespace(returncode=0, stdout='')
            return SimpleNamespace(returncode=0, stdout='')

        with patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ok = portal._restore_systemd_service_state(
                'hy2-anytls', {'active': 'active', 'enabled': 'enabled'})

        self.assertTrue(ok)
        self.assertIn(['systemctl', 'reset-failed', 'hy2-anytls'], calls)
        self.assertIn(['systemctl', 'restart', 'hy2-anytls'], calls)
        self.assertLess(
            calls.index(['systemctl', 'reset-failed', 'hy2-anytls']),
            calls.index(['systemctl', 'restart', 'hy2-anytls']),
        )
        self.assertNotIn(['systemctl', 'start', 'hy2-anytls'], calls)

    def test_restoring_inactive_service_still_stops_without_restart(self):
        calls = []
        state = {'active': 'active', 'enabled': 'disabled'}

        def fake_run(args, **kwargs):
            calls.append(list(args))
            if args[:2] == ['systemctl', 'is-active']:
                return SimpleNamespace(returncode=0, stdout=state['active'])
            if args[:2] == ['systemctl', 'is-enabled']:
                return SimpleNamespace(returncode=0, stdout=state['enabled'])
            if args[:2] == ['systemctl', 'stop']:
                state['active'] = 'inactive'
                return SimpleNamespace(returncode=0, stdout='')
            return SimpleNamespace(returncode=0, stdout='')

        with patch.object(portal.subprocess, 'run', side_effect=fake_run):
            ok = portal._restore_systemd_service_state(
                'hy2-tuic', {'active': 'inactive', 'enabled': 'disabled'})

        self.assertTrue(ok)
        self.assertIn(['systemctl', 'stop', 'hy2-tuic'], calls)
        self.assertNotIn(['systemctl', 'restart', 'hy2-tuic'], calls)


if __name__ == '__main__':
    unittest.main()
