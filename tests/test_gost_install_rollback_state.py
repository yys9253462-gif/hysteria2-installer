"""回归测试：GOST 安装失败回滚时先清理失败计数并精确还原原有 active / enabled 状态。"""
import ast
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(SRC)


def _extract_restore_gost_assets():
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == 'restore_gost_assets':
            return node
    raise AssertionError('找不到 restore_gost_assets 函数')


def _run_restore(old_has_bin, old_active, old_enabled):
    fn_node = _extract_restore_gost_assets()
    # 剥离 nonlocal assets_modified 以便独立执行该函数体，测试其真实分支行为。
    body = [stmt for stmt in fn_node.body if not isinstance(stmt, ast.Nonlocal)]
    wrapper = ast.FunctionDef(
        name='restore_gost_assets',
        args=fn_node.args,
        body=body,
        decorator_list=[],
        returns=None,
    )
    mod = ast.Module(body=[wrapper], type_ignores=[])
    ast.fix_missing_locations(mod)

    calls = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        gost_binary = root / 'gost'
        cert_dir = root / 'cert'
        old_assets = {
            gost_binary: (b'old-gost-bin', 0o755) if old_has_bin else None,
        }
        ns = {
            'assets_modified': False,
            'old_assets': old_assets,
            'gost_binary': gost_binary,
            'had_cert_dir': True,
            'cert_dir': cert_dir,
            'data_lock': threading.RLock(),
            'had_proxy_services': False,
            'previous_proxy_services': [],
            'data': {},
            'old_gost_active': old_active,
            'old_gost_enabled': old_enabled,
            'os': os,
            'subprocess': SimpleNamespace(run=fake_run),
        }
        exec(compile(mod, str(ROOT / 'portal.py'), 'exec'), ns)
        ns['restore_gost_assets']()
    return calls


class GostInstallRollbackStateTests(unittest.TestCase):
    def test_active_but_disabled_gost_resets_failed_restarts_and_stays_disabled(self):
        calls = _run_restore(old_has_bin=True, old_active=True, old_enabled=False)
        self.assertIn(['systemctl', 'reset-failed', 'gost'], calls)
        self.assertIn(['systemctl', 'restart', 'gost'], calls)
        self.assertLess(
            calls.index(['systemctl', 'reset-failed', 'gost']),
            calls.index(['systemctl', 'restart', 'gost']),
        )
        self.assertIn(['systemctl', 'disable', 'gost'], calls)
        self.assertNotIn(['systemctl', 'enable', 'gost'], calls)

    def test_inactive_but_enabled_gost_is_stopped_and_kept_enabled(self):
        calls = _run_restore(old_has_bin=True, old_active=False, old_enabled=True)
        self.assertIn(['systemctl', 'enable', 'gost'], calls)
        self.assertIn(['systemctl', 'stop', 'gost'], calls)
        self.assertNotIn(['systemctl', 'restart', 'gost'], calls)

    def test_absent_gost_is_disabled_and_stopped(self):
        calls = _run_restore(old_has_bin=False, old_active=False, old_enabled=False)
        self.assertIn(['systemctl', 'disable', '--now', 'gost'], calls)
        self.assertIn(['systemctl', 'stop', 'gost'], calls)


if __name__ == '__main__':
    unittest.main()
