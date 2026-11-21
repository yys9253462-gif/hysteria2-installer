"""回归测试：整机停用恢复 reset-failed 超时隔离、自更新脚本端口/等待界限校验及出站纯 ASCII 端口校验。"""
import ast
import copy
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def _extract_set_traffic_suspension(data, save_data):
    tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
    fn_node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == '_set_traffic_suspension'
    )
    env = dict(
        portal.__dict__,
        data=data,
        data_lock=threading.RLock(),
        save_data=save_data,
        TRAFFIC_SUSPEND_UNITS=('hysteria-server', 'xray'),
        _unit_active=lambda u: True,
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(fn_node)], type_ignores=[])),
                 '<suspend-test>', 'exec'), env)
    return env['_set_traffic_suspension']


class SuspendResetFailedUpdateBoundsAndOutboundAsciiTests(unittest.TestCase):
    def test_resume_and_compensation_still_start_unit_when_reset_failed_times_out(self):
        """恢复停用或落盘失败补偿拉起时，systemctl reset-failed 超时不得跳过后续 systemctl start。"""
        # 1) 恢复路径
        data = {'traffic_suspend': {'suspended': True, 'units': ['hysteria-server'], 'since': 100}}
        fn = _extract_set_traffic_suspension(data, Mock())
        calls = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            if cmd[:2] == ['systemctl', 'reset-failed']:
                raise subprocess.TimeoutExpired(cmd, 5)
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with patch.object(portal.subprocess, 'run', side_effect=fake_run):
            new_state, results = fn(False)
        self.assertTrue(results.get('hysteria-server'), f'reset-failed 超时不应导致跳过 start: {calls}')
        self.assertFalse(new_state.get('suspended'))
        self.assertIn(['systemctl', 'start', 'hysteria-server'], calls)

        # 2) 停用落盘失败补偿拉起路径
        data2 = {'traffic_suspend': {'suspended': False}}
        fn2 = _extract_set_traffic_suspension(data2, Mock(side_effect=OSError('disk full')))
        calls2 = []

        def fake_run2(cmd, **kw):
            calls2.append(list(cmd))
            if cmd[:2] == ['systemctl', 'reset-failed']:
                raise subprocess.TimeoutExpired(cmd, 5)
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with patch.object(portal.subprocess, 'run', side_effect=fake_run2):
            with self.assertRaises(OSError):
                fn2(True)
        self.assertIn(['systemctl', 'start', 'hysteria-server'], calls2)

    def test_portal_update_restart_script_rejects_invalid_port_and_wait_seconds(self):
        """portal_update_restart_script 必须拒绝布尔/越界 port 与非法 wait_seconds。"""
        for bad_port in (True, False, 0, -1, 65536):
            with self.subTest(bad_port=bad_port):
                with self.assertRaises(ValueError):
                    portal.portal_update_restart_script(bad_port, [], [])
        for bad_wait in (True, False, 0, -5, 601):
            with self.subTest(bad_wait=bad_wait):
                with self.assertRaises(ValueError):
                    portal.portal_update_restart_script(8080, [], [], wait_seconds=bad_wait)

    def test_validate_outbound_rejects_fullwidth_socks5_ports(self):
        """validate_outbound 的 SOCKS5 IPv4/域名与 IPv6 端口均必须为纯 ASCII 数字，拒绝全角数字。"""
        for bad_addr in ('1.2.3.4:\uff11\uff10\uff18\uff10', '[::1]:\uff11\uff10\uff18\uff10'):
            with self.subTest(bad_addr=bad_addr):
                ok, cleaned, err = portal.validate_outbound({
                    'name': 'p1',
                    'type': 'socks5',
                    'addr': bad_addr,
                })
                self.assertFalse(ok, f'全角端口 {bad_addr!r} 不应通过校验')
                self.assertIsNone(cleaned)


if __name__ == '__main__':
    unittest.main()
