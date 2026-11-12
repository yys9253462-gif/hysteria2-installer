"""计量模块重启 Xray 前先清失败计数（2026-11-12 修）。

门户其它重启 Xray 的地方都先 reset-failed；enable_iplimit_routing / enable_reality_online
没有：Xray 刚连续重启过、撞上 StartLimitBurst 时 restart 会被直接拒绝，回滚那次同样起不来，
Xray 一直停着，Reality / VMess / VLESS-Enc 用户全部断线。正常路径与回滚路径都要清。
"""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'xcfg_restart', Path(__file__).resolve().parents[1] / 'usage-meter-xray-config-20261007-v1.py')
xcfg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xcfg)

RESET = ['systemctl', 'reset-failed', 'xray']
RESTART = ['systemctl', 'restart', 'xray']


class XrayRestartClearsFailedStateTests(unittest.TestCase):
    def run_enable(self, enable, config, fail_first_restart):
        calls = []

        def run(args, **kwargs):
            calls.append(list(args))
            if args == RESTART and fail_first_restart and calls.count(RESTART) == 1:
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, '', '')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'xray.json'
            path.write_text(json.dumps(config), encoding='utf-8')
            with patch.object(xcfg.subprocess, 'run', side_effect=run):
                if fail_first_restart:
                    with self.assertRaises(subprocess.CalledProcessError):
                        enable(str(path), '/x', '127.0.0.1:1')
                else:
                    enable(str(path), '/x', '127.0.0.1:1')
        return calls

    def check(self, enable, config):
        for fail in (False, True):
            with self.subTest(rollback=fail):
                calls = self.run_enable(enable, config, fail)
                restarts = [i for i, c in enumerate(calls) if c == RESTART]
                self.assertEqual(len(restarts), 2 if fail else 1, calls)
                for i in restarts:
                    self.assertEqual(calls[i - 1], RESET, 'restart without reset-failed: %s' % calls)

    def test_iplimit_routing(self):
        self.check(xcfg.enable_iplimit_routing, {
            'inbounds': [{'tag': 'vless-reality-in', 'protocol': 'vless', 'port': 443,
                          'settings': {'clients': []}}],
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            'api': {'tag': 'usage-meter-api', 'services': ['StatsService']},
        })

    def test_reality_online(self):
        self.check(xcfg.enable_reality_online, {
            'inbounds': [{'settings': {'clients': [{'id': 'fixture', 'level': 0}]}}],
            'outbounds': [],
        })


if __name__ == '__main__':
    unittest.main()
