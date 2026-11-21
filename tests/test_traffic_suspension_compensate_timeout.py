"""回归测试：_set_traffic_suspension 保存失败补偿必须隔离超时异常不跳过其余服务，且补偿启动前先 reset-failed、跳过已退役服务。"""

import copy
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


def _extract_set_traffic_suspension(ns):
    src = (ROOT / 'portal.py').read_text(encoding='utf-8')
    start = src.index('    def _set_traffic_suspension(suspend):')
    end = src.index('    # 计量每 5 秒对每个来源采样一次', start)
    lines = src[start:end].splitlines()
    dedented = '\n'.join(ln[4:] if ln.startswith('    ') else ln for ln in lines)
    exec(compile(dedented, '<_set_traffic_suspension>', 'exec'), ns)
    return ns['_set_traffic_suspension']


class TrafficSuspensionCompensateTimeoutTests(unittest.TestCase):
    def test_save_failure_compensate_continues_after_timeout_and_resets_failed_before_start(self):
        """停用保存失败补偿拉起服务时，首服务超时不得中断其余服务补偿，且拉起前须先 reset-failed。"""
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd == ['systemctl', 'start', 'hysteria-server']:
                raise subprocess.TimeoutExpired(cmd, 20)
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        data = {}
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            TRAFFIC_SUSPEND_UNITS=('hysteria-server', 'xray'),
            ANYTLS_SERVICE=portal.ANYTLS_SERVICE,
            TUIC_SERVICE=portal.TUIC_SERVICE,
            _unit_active=lambda u: True,
            save_data=mock.Mock(side_effect=OSError('disk full')),
            subprocess=SimpleNamespace(
                run=fake_run,
                TimeoutExpired=subprocess.TimeoutExpired,
                SubprocessError=subprocess.SubprocessError,
            ),
            copy=copy,
            time=time,
        )
        fn = _extract_set_traffic_suspension(ns)
        with self.assertRaises(OSError) as ctx:
            fn(True)
        self.assertIn('disk full', str(ctx.exception))
        self.assertIn(['systemctl', 'reset-failed', 'xray'], calls,
                      '补偿拉起服务前未先执行 systemctl reset-failed')
        self.assertIn(['systemctl', 'start', 'xray'], calls,
                      'hysteria-server 补偿超时导致跳过了后续 xray 服务的补偿拉起')

    def test_resume_save_failure_compensate_skips_retired_protocol(self):
        """恢复保存失败补偿停服时，不得对停用期间已退役的协议发多余 systemctl stop。"""
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        data = {
            'traffic_suspend': {'suspended': True, 'units': ['hysteria-server', portal.ANYTLS_SERVICE], 'since': 100},
            'anytls_config': {'enabled': False},
        }
        ns = dict(
            portal.__dict__,
            data=data,
            data_lock=threading.RLock(),
            TRAFFIC_SUSPEND_UNITS=('hysteria-server', portal.ANYTLS_SERVICE),
            ANYTLS_SERVICE=portal.ANYTLS_SERVICE,
            TUIC_SERVICE=portal.TUIC_SERVICE,
            _unit_active=lambda u: False,
            save_data=mock.Mock(side_effect=OSError('disk full')),
            subprocess=SimpleNamespace(
                run=fake_run,
                TimeoutExpired=subprocess.TimeoutExpired,
                SubprocessError=subprocess.SubprocessError,
            ),
            copy=copy,
            time=time,
        )
        fn = _extract_set_traffic_suspension(ns)
        with self.assertRaises(OSError):
            fn(False)
        self.assertIn(['systemctl', 'stop', 'hysteria-server'], calls)
        self.assertNotIn(['systemctl', 'stop', portal.ANYTLS_SERVICE], calls,
                         '对本来已退役未拉起的 AnyTLS 发送了多余的补偿 stop')


if __name__ == '__main__':
    unittest.main()
